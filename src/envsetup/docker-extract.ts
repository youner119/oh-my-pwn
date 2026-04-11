/**
 * Extract `libc.so.6` and `ld-linux*.so.*` out of a built docker image into
 * the challenge's `.omp/artifacts/` directory.
 *
 * Strategy:
 *
 *   1. `docker create <image>` to materialise a stopped container we can
 *      `docker cp` files out of without running the entrypoint.
 *   2. For each well-known glibc libc path, try `docker cp` until one
 *      succeeds. The first hit wins.
 *   3. If no libc candidate hit, fall back to checking the binary itself
 *      for a `PT_INTERP` segment via `hasInterpSegment`. If absent, the
 *      binary is statically linked — return `{ staticLinked: true }` and
 *      let the caller mark `libc_version = "static"` in state.
 *   4. Otherwise throw {@link EnvSetupError} (`libc-not-found`) with the
 *      full list of candidate paths attempted and a best-effort listing
 *      of `/lib*` / `/usr/lib*` from the image, so the user (or a future
 *      LLM agent wrapping this library) can diagnose without re-running.
 *   5. Once libc is in hand, attempt the same scan for `ld-*.so.*`. The
 *      ld file is optional — some images do not expose it at the
 *      conventional path. Returning `ldPath: undefined` is fine; the
 *      journal will note it.
 *   6. Always run `docker rm -f <container>` in `finally` so we don't
 *      leak stopped containers across runs.
 */

import { statSync, unlinkSync } from "node:fs"
import { basename, join } from "node:path"
import type { DockerRunner } from "./docker-runner"
import { EnvSetupError } from "./envsetup-error"
import { hasInterpSegment } from "./elf-mitigations"

/** Standard libc paths to try, in priority order. */
const LIBC_CANDIDATES: readonly string[] = [
  "/lib/x86_64-linux-gnu/libc.so.6",
  "/lib64/libc.so.6",
  "/lib/libc.so.6",
  "/usr/lib/x86_64-linux-gnu/libc.so.6",
  "/usr/lib64/libc.so.6",
  "/usr/lib/libc.so.6",
  "/lib/i386-linux-gnu/libc.so.6",
  "/usr/lib/i386-linux-gnu/libc.so.6",
  "/lib32/libc.so.6",
]

/** Standard ld-linux paths to try, in priority order. */
const LD_CANDIDATES: readonly string[] = [
  "/lib64/ld-linux-x86-64.so.2",
  "/lib/ld-linux-x86-64.so.2",
  "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
  "/lib/ld-linux.so.2",
  "/lib/i386-linux-gnu/ld-linux.so.2",
  "/lib32/ld-linux.so.2",
]

/** Directories the failure-listing probe inspects when libc is not found. */
const LISTING_PROBE_DIRS: readonly string[] = [
  "/lib",
  "/lib64",
  "/lib/x86_64-linux-gnu",
  "/usr/lib",
  "/usr/lib/x86_64-linux-gnu",
]

export interface DockerExtractDynamicResult {
  staticLinked: false
  /** Absolute path to the libc copied into `.omp/artifacts/`. */
  libcPath: string
  /** Path inside the container that the libc was sourced from. */
  libcImagePath: string
  /** Absolute path to the ld interpreter copied into `.omp/artifacts/`, if found. */
  ldPath?: string
  /** Path inside the container that ld was sourced from, if found. */
  ldImagePath?: string
}

export interface DockerExtractStaticResult {
  staticLinked: true
}

export type DockerExtractResult =
  | DockerExtractDynamicResult
  | DockerExtractStaticResult

export interface DockerExtractInputs {
  imageTag: string
  binaryPath: string
  artifactsDir: string
  challengeDir: string
}

/**
 * Extract libc/ld from a docker image. See module doc for the algorithm.
 *
 * @throws EnvSetupError on `libc-not-found`, `extraction-failed`,
 *         or spawn-level docker failures (translated to
 *         `docker-not-available`).
 */
export function extractLibcAndLd(
  inputs: DockerExtractInputs,
  runner: DockerRunner,
): DockerExtractResult {
  const { imageTag, binaryPath, artifactsDir, challengeDir } = inputs

  let containerId: string
  try {
    const createResult = runner.run(["create", imageTag])
    if (createResult.exitCode !== 0) {
      throw new EnvSetupError({
        kind: "extraction-failed",
        challengeDir,
        message: `docker create ${imageTag} failed (exit ${createResult.exitCode}): ${truncate(createResult.stderr.toString("utf-8"), 1024)}`,
        imageTag,
        imagePath: "<container create>",
        exitCode: createResult.exitCode,
        stderr: truncate(createResult.stderr.toString("utf-8"), 1024),
      })
    }
    containerId = createResult.stdout.toString("utf-8").trim()
    if (containerId === "") {
      throw new EnvSetupError({
        kind: "extraction-failed",
        challengeDir,
        message: `docker create ${imageTag} returned empty container id`,
        imageTag,
        imagePath: "<container create>",
        exitCode: 0,
        stderr: "",
      })
    }
  } catch (err) {
    if (err instanceof EnvSetupError) {
      throw err
    }
    throw translateSpawnError(err, challengeDir)
  }

  try {
    const libc = tryCopy(
      containerId,
      LIBC_CANDIDATES,
      artifactsDir,
      "libc.so.6",
      challengeDir,
      runner,
    )
    if (libc === null) {
      // No libc anywhere. Decide static vs error based on PT_INTERP.
      if (!hasInterpSegment(binaryPath)) {
        return { staticLinked: true }
      }
      const listing = bestEffortListing(imageTag, runner)
      throw new EnvSetupError({
        kind: "libc-not-found",
        challengeDir,
        message: `Could not find libc.so.6 at any standard path inside ${imageTag}.`,
        imageTag,
        candidatesTried: [...LIBC_CANDIDATES],
        imageListing: listing,
      })
    }

    const ld = tryCopy(
      containerId,
      LD_CANDIDATES,
      artifactsDir,
      undefined, // keep the original basename for ld
      challengeDir,
      runner,
    )

    return {
      staticLinked: false,
      libcPath: libc.localPath,
      libcImagePath: libc.imagePath,
      ldPath: ld?.localPath,
      ldImagePath: ld?.imagePath,
    }
  } finally {
    // Best effort: never leak containers, but never throw out of cleanup.
    try {
      runner.run(["rm", "-f", containerId])
    } catch {
      // intentionally ignored
    }
  }
}

interface CopySuccess {
  imagePath: string
  localPath: string
}

/**
 * Try each candidate path inside the container and copy the first hit out
 * to `artifactsDir`. Returns `null` if every candidate misses.
 *
 * Always passes `docker cp -L` so symlinks (e.g. `libc.so.6 → libc-2.31.so`)
 * are dereferenced — we want a self-contained file in `.omp/artifacts/`,
 * not a symlink that points into a path that does not exist on the host.
 *
 * `localBasename` overrides the destination filename. When `undefined`,
 * the destination uses the basename of the source path (so multiple
 * `ld-linux-*` variants keep their natural names).
 */
function tryCopy(
  containerId: string,
  candidates: readonly string[],
  artifactsDir: string,
  localBasename: string | undefined,
  challengeDir: string,
  runner: DockerRunner,
): CopySuccess | null {
  for (const candidate of candidates) {
    const destBasename = localBasename ?? basename(candidate)
    const dest = join(artifactsDir, destBasename)
    let result
    try {
      result = runner.run(["cp", "-L", `${containerId}:${candidate}`, dest])
    } catch (err) {
      throw translateSpawnError(err, challengeDir)
    }
    if (result.exitCode !== 0) {
      // Non-zero exit means "not present" or transient cp issue. Keep
      // scanning candidates. We surface a cumulative `libc-not-found`
      // only when every candidate misses.
      continue
    }
    if (!fileExistsAndNonEmpty(dest)) {
      // docker cp claimed success but produced an empty/missing file.
      // Defensive: clean up and treat as miss.
      safeUnlink(dest)
      continue
    }
    return { imagePath: candidate, localPath: dest }
  }
  return null
}

function fileExistsAndNonEmpty(path: string): boolean {
  try {
    const s = statSync(path)
    return s.isFile() && s.size > 0
  } catch {
    return false
  }
}

function safeUnlink(path: string): void {
  try {
    unlinkSync(path)
  } catch {
    // intentionally ignored
  }
}

/**
 * Best-effort listing of `/lib*` directories inside the image, used as
 * extra context for the `libc-not-found` error.
 *
 * Returns `undefined` when the image has no shell or `ls` (e.g.
 * scratch-based images). The error path tolerates that.
 */
function bestEffortListing(imageTag: string, runner: DockerRunner): string[] | undefined {
  const cmd = LISTING_PROBE_DIRS.map((dir) => `ls -la ${dir} 2>/dev/null`).join("; ")
  let result
  try {
    result = runner.run([
      "run",
      "--rm",
      "--entrypoint",
      "sh",
      imageTag,
      "-c",
      cmd,
    ])
  } catch {
    return undefined
  }
  if (result.exitCode !== 0) {
    return undefined
  }
  const lines = result.stdout.toString("utf-8").split(/\r?\n/u).filter((l) => l !== "")
  return lines.length > 0 ? lines : undefined
}

function truncate(text: string, max: number): string {
  if (text.length <= max) {
    return text
  }
  return `${text.slice(0, max)}\n... (truncated, ${text.length - max} more bytes)`
}

function translateSpawnError(err: unknown, challengeDir: string): EnvSetupError {
  const code = (err as NodeJS.ErrnoException | undefined)?.code
  return new EnvSetupError({
    kind: "docker-not-available",
    challengeDir,
    code,
    message:
      code === "ENOENT"
        ? "docker binary not found in PATH. Install docker and retry."
        : `Failed to spawn docker: ${(err as Error).message}`,
  })
}
