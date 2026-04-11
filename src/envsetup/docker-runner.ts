/**
 * Single chokepoint for every `docker` invocation in the EnvSetup library.
 *
 * Why this exists: docker is an external system, slow to invoke, and
 * impossible to drive from a unit test in CI. Routing every call through
 * this interface lets us:
 *
 *   - Run real docker in `T05` (the M1 user-test gate) and beyond, via
 *     {@link realDockerRunner}.
 *   - Substitute a fake runner in unit tests
 *     (see `./fake-docker-runner.ts`) so the rest of the EnvSetup library
 *     is fully testable without docker present.
 *
 * Contract: the runner does **not** throw on non-zero exit codes — many
 * docker subcommands (e.g. `docker image inspect`) use exit codes as
 * information, not failure. The caller decides what each non-zero means.
 * The runner DOES throw on **spawn-level** failures (binary missing,
 * permission denied, timeout) so the caller can translate those into a
 * top-level {@link import("./envsetup-error").EnvSetupError} (typically
 * `docker-not-available`).
 */

import { spawnSync } from "node:child_process"

export interface DockerRunResult {
  /** Process exit code. `-1` if the process did not exit normally. */
  exitCode: number
  stdout: Buffer
  stderr: Buffer
}

export interface DockerRunOptions {
  /** Working directory for the spawned process (e.g. challenge folder). */
  cwd?: string
  /** Bytes piped to docker stdin (e.g. context tarball for `docker build -`). */
  input?: Buffer | string
  /** Hard timeout in milliseconds. Omit for no timeout. */
  timeoutMs?: number
}

export interface DockerRunner {
  /**
   * Spawn `docker <args>` synchronously and return the result.
   *
   * @throws Underlying spawn error (with `code` like "ENOENT") on
   *         spawn-level failures. Does NOT throw on non-zero process exit.
   */
  run(args: readonly string[], opts?: DockerRunOptions): DockerRunResult
}

/**
 * Real docker runner backed by {@link spawnSync}.
 *
 * Used by every production code path. Never substituted at runtime — only
 * tests inject a different implementation.
 */
export const realDockerRunner: DockerRunner = {
  run(args, opts = {}) {
    const result = spawnSync("docker", [...args], {
      cwd: opts.cwd,
      input: opts.input,
      timeout: opts.timeoutMs,
    })

    if (result.error !== undefined && result.error !== null) {
      // Common cases here: ENOENT (docker not installed), EACCES (no
      // permission to /var/run/docker.sock), ETIMEDOUT (we hit timeoutMs).
      // Re-throw verbatim so the caller can read `err.code` and translate.
      throw result.error
    }

    return {
      exitCode: result.status ?? -1,
      stdout: toBuffer(result.stdout),
      stderr: toBuffer(result.stderr),
    }
  },
}

function toBuffer(value: Buffer | string | null | undefined): Buffer {
  if (value === null || value === undefined) {
    return Buffer.alloc(0)
  }
  if (typeof value === "string") {
    return Buffer.from(value, "utf-8")
  }
  return value
}
