/**
 * `patchelf` wrapper that rewrites a challenge binary's interpreter and
 * rpath so it loads the libc/ld extracted from the docker image instead of
 * the host's. This is the standard pwntools-style "match the remote libc
 * exactly" workflow.
 *
 * Idempotent design:
 *
 *   1. If a backup of the original binary does not exist yet, copy
 *      `binaryPath` to `backupPath` so the input contract identity is
 *      preserved before any modification.
 *   2. Always restore `binaryPath` from the backup before patching. This
 *      makes re-running EnvSetup against new artifacts (e.g. after the
 *      Docker image was rebuilt) deterministic — every patch starts from
 *      the original bytes.
 *   3. Run `patchelf --set-interpreter <ld> --set-rpath <artifactsDir>
 *      <binaryPath>`.
 *   4. Recompute the SHA-256 of the patched bytes so the caller can update
 *      `state.binary_sha256`.
 *
 * Failure modes:
 *
 *   - `patchelf` not in PATH (`ENOENT`) →
 *     `EnvSetupError({ kind: "patchelf-not-available" })`. The caller can
 *     either ask the user to install patchelf, or fall back to the
 *     unpatched binary by passing `--no-patch`.
 *   - `patchelf` exits non-zero (e.g. binary is too small to add an rpath
 *     entry, or already malformed) →
 *     `EnvSetupError({ kind: "patchelf-failed" })`, with stderr attached.
 *
 * Subprocess injection: tests pass a fake `spawn` via `opts.spawn` so the
 * whole patch path is exercisable without `patchelf` actually present. The
 * default uses `node:child_process.spawnSync`. This is the smallest
 * possible DI seam — no parallel `PatchelfRunner` interface, no second
 * fake-runner module.
 */

import { spawnSync } from "node:child_process"
import { copyFileSync, existsSync, readFileSync } from "node:fs"
import { createHash } from "node:crypto"
import { EnvSetupError } from "./envsetup-error"

export interface PatchelfInputs {
  /** Absolute path to the (active) challenge binary. Will be patched in place. */
  binaryPath: string
  /** Absolute path where the original is preserved (under .omp/artifacts/). */
  backupPath: string
  /** Absolute path to the extracted ld interpreter from the docker image. */
  interpreterPath: string
  /** Absolute path to the directory containing the extracted libc.so.6. */
  libcDir: string
  /** OmP challenge_dir, used to thread challengeDir into any thrown EnvSetupError. */
  challengeDir: string
}

export interface SpawnResult {
  exitCode: number
  stdout: Buffer
  stderr: Buffer
}

export type SpawnFn = (
  cmd: string,
  args: readonly string[],
) => SpawnResult

export interface PatchelfOptions {
  /** Inject a fake subprocess runner. Default uses `spawnSync`. */
  spawn?: SpawnFn
}

export interface PatchelfResult {
  /** True iff `backupPath` did not exist before this call. */
  backupCreated: boolean
  /** SHA-256 of the binary after patching. */
  patchedSha256: string
  /** SHA-256 of the original binary (= the backup contents). */
  originalSha256: string
}

const realSpawn: SpawnFn = (cmd, args) => {
  const result = spawnSync(cmd, [...args])
  if (result.error !== undefined && result.error !== null) {
    throw result.error
  }
  return {
    exitCode: result.status ?? -1,
    stdout: result.stdout ?? Buffer.alloc(0),
    stderr: result.stderr ?? Buffer.alloc(0),
  }
}

/**
 * Patch the binary's interpreter and rpath so it picks up the docker
 * image's libc/ld at runtime. See module doc for the algorithm.
 */
export function patchBinaryInterpreter(
  inputs: PatchelfInputs,
  opts: PatchelfOptions = {},
): PatchelfResult {
  const spawn = opts.spawn ?? realSpawn

  // Step 1: backup the original if not already saved.
  let backupCreated = false
  if (!existsSync(inputs.backupPath)) {
    copyFileSync(inputs.binaryPath, inputs.backupPath)
    backupCreated = true
  }
  // The backup is the canonical original now.
  const originalSha256 = sha256File(inputs.backupPath)

  // Step 2: restore binary_path from backup so the patch always starts
  // from a clean original. This makes re-runs idempotent.
  copyFileSync(inputs.backupPath, inputs.binaryPath)

  // Step 3: run patchelf.
  const args = [
    "--set-interpreter",
    inputs.interpreterPath,
    "--set-rpath",
    inputs.libcDir,
    inputs.binaryPath,
  ]
  let result: SpawnResult
  try {
    result = spawn("patchelf", args)
  } catch (err) {
    throw translatePatchelfSpawnError(err, inputs.challengeDir)
  }

  if (result.exitCode !== 0) {
    throw new EnvSetupError({
      kind: "patchelf-failed",
      challengeDir: inputs.challengeDir,
      binaryPath: inputs.binaryPath,
      exitCode: result.exitCode,
      stderr: truncate(result.stderr.toString("utf-8"), 1024),
      message:
        `patchelf failed with exit code ${result.exitCode}. ` +
        `stderr: ${truncate(result.stderr.toString("utf-8"), 200)}`,
    })
  }

  // Step 4: recompute sha after the patch.
  const patchedSha256 = sha256File(inputs.binaryPath)

  return { backupCreated, patchedSha256, originalSha256 }
}

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex")
}

function translatePatchelfSpawnError(
  err: unknown,
  challengeDir: string,
): EnvSetupError {
  const code = (err as NodeJS.ErrnoException | undefined)?.code
  return new EnvSetupError({
    kind: "patchelf-not-available",
    challengeDir,
    code,
    message:
      code === "ENOENT"
        ? "patchelf binary not found in PATH. Install it with `apt install patchelf` (Ubuntu/Debian) or `dnf install patchelf` (Fedora), or pass --no-patch to skip the interpreter rewrite."
        : `Failed to spawn patchelf: ${(err as Error).message}`,
  })
}

function truncate(text: string, max: number): string {
  if (text.length <= max) {
    return text
  }
  return `${text.slice(0, max)}\n... (truncated, ${text.length - max} more bytes)`
}
