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
import { copyFileSync, existsSync, mkdirSync, readFileSync } from "node:fs"
import { dirname } from "node:path"
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

/* ── omp-setup agent generic patchelf (T07) ────────────────────────────── */

/**
 * Generic ELF patcher used by `omp_setup_patch_elf` (T07).
 *
 * Differences vs the legacy `patchBinaryInterpreter`:
 *
 *   - **No backup, no restore-before-patch.** The omp-setup design (D3)
 *     keeps the input file untouched by writing patched output to
 *     `dstPath` (when supplied). If `dstPath === undefined`, the patch is
 *     applied in-place to `srcPath` — appropriate for libraries already
 *     copied into `.omp/artifacts/` or `workspace/<id>/`.
 *   - **`--replace-needed` instead of `--set-rpath`.** NEEDED entries are
 *     rewritten to absolute paths so ld does not consult any search path.
 *     Each `replacements[soname] = absPath` produces one
 *     `--replace-needed <soname> <absPath>` flag pair.
 *   - **`--set-interpreter` is optional.** Libraries do not carry an
 *     interpreter; pass `undefined` to skip the flag.
 *   - **No-op safety.** When neither `interpreter` nor `replacements` is
 *     supplied, patchelf is not invoked. The function still performs the
 *     copy (if `dstPath !== srcPath`) and returns sha matching for both
 *     fields — callers can use this as a defensive "validate but don't
 *     mutate" path.
 */
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
