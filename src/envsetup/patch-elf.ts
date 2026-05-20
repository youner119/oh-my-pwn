/**
 * `patchelf` wrapper used by the `omp_setup_patch_elf` tool (T07).
 *
 * Writes patched output to `dstPath` when supplied (input file untouched —
 * spec D3 invariant), or runs in-place on `srcPath` when `dstPath` is
 * omitted (used for libraries already copied into `.omp/artifacts/` or
 * `workspace/<id>/`).
 *
 * Uses `--set-interpreter` (optional) + `--replace-needed` so NEEDED
 * entries are rewritten to absolute paths and ld does not consult any
 * search path. Each `replacements[soname] = absPath` produces one
 * `--replace-needed <soname> <absPath>` flag pair.
 *
 * No-op safety: when neither `interpreter` nor `replacements` is supplied,
 * patchelf is not invoked. The function still performs the copy (if
 * `dstPath !== srcPath`) and returns sha matching for both fields.
 *
 * Failure modes:
 *   - `patchelf` not in PATH (`ENOENT`) →
 *     `EnvSetupError({ kind: "patchelf-not-available" })`.
 *   - `patchelf` exits non-zero →
 *     `EnvSetupError({ kind: "patchelf-failed" })` with stderr attached.
 *
 * Subprocess injection: tests pass a fake `spawn` via `opts.spawn` so the
 * whole patch path is exercisable without `patchelf` actually present.
 */

import { spawnSync } from "node:child_process"
import { copyFileSync, mkdirSync, readFileSync } from "node:fs"
import { dirname } from "node:path"
import { createHash } from "node:crypto"
import { EnvSetupError } from "./envsetup-error"

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

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex")
}

/* ── omp-setup agent generic patchelf (T07) ────────────────────────────── */
export interface PatchElfInputs {
  /** Absolute path to the source ELF. Never modified when `dstPath` differs. */
  srcPath: string
  /**
   * Absolute path for the patched copy. When omitted, patchelf runs
   * in-place on `srcPath`. Parent directory is auto-created.
   */
  dstPath?: string
  /** Absolute path to set as ELF interpreter (`--set-interpreter`). */
  interpreter?: string
  /**
   * SONAME → absolute path map. Each entry becomes one
   * `--replace-needed <soname> <absPath>` argument pair. Use empty map or
   * `undefined` to skip NEEDED rewrites.
   */
  replacements?: Record<string, string>
  /** Optional challenge_dir for error reporting. */
  challengeDir?: string
}

export interface PatchElfResult {
  /** Effective patched path (`dstPath ?? srcPath`). */
  patchedPath: string
  /** SHA-256 of the source ELF BEFORE any modification. */
  originalSha256: string
  /** SHA-256 of `patchedPath` AFTER patchelf runs. */
  patchedSha256: string
  /** True iff patchelf was actually invoked (false on the no-op path). */
  invokedPatchelf: boolean
}

/**
 * Apply patchelf to an ELF file with the generic input shape used by
 * `omp_setup_patch_elf`. See the type doc above for semantics.
 *
 * @throws EnvSetupError on `patchelf-not-available` or `patchelf-failed`.
 */
export function patchElf(
  inputs: PatchElfInputs,
  opts: PatchelfOptions = {},
): PatchElfResult {
  const spawn = opts.spawn ?? realSpawn

  const target = inputs.dstPath ?? inputs.srcPath

  // Original sha — captured BEFORE any copy/patch so callers can detect
  // tampering or compare to a recorded identity.
  const originalSha256 = sha256File(inputs.srcPath)

  // Copy src → dst (only when the two paths differ).
  if (inputs.dstPath !== undefined && inputs.dstPath !== inputs.srcPath) {
    mkdirSync(dirname(inputs.dstPath), { recursive: true })
    copyFileSync(inputs.srcPath, inputs.dstPath)
  }

  // Build patchelf args from interpreter + replacements. No args ⇒ no-op.
  const args: string[] = []
  if (inputs.interpreter !== undefined && inputs.interpreter !== "") {
    args.push("--set-interpreter", inputs.interpreter)
  }
  if (inputs.replacements !== undefined) {
    for (const [soname, absPath] of Object.entries(inputs.replacements)) {
      args.push("--replace-needed", soname, absPath)
    }
  }

  if (args.length === 0) {
    // No-op: copy already done (if any), sha matches original.
    return {
      patchedPath: target,
      originalSha256,
      patchedSha256: originalSha256,
      invokedPatchelf: false,
    }
  }

  args.push(target)
  let result: SpawnResult
  try {
    result = spawn("patchelf", args)
  } catch (err) {
    throw translatePatchelfSpawnError(err, inputs.challengeDir ?? "")
  }

  if (result.exitCode !== 0) {
    throw new EnvSetupError({
      kind: "patchelf-failed",
      challengeDir: inputs.challengeDir ?? "",
      binaryPath: target,
      exitCode: result.exitCode,
      stderr: truncate(result.stderr.toString("utf-8"), 1024),
      message:
        `patchelf failed with exit code ${result.exitCode} on ${target}. ` +
        `stderr: ${truncate(result.stderr.toString("utf-8"), 200)}`,
    })
  }

  const patchedSha256 = sha256File(target)
  return {
    patchedPath: target,
    originalSha256,
    patchedSha256,
    invokedPatchelf: true,
  }
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
