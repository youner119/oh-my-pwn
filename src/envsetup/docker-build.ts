/**
 * `docker build` wrapper with cache-hit reuse logic.
 *
 * Responsibilities:
 *
 *   - Decide whether the existing image (recorded in `state.docker_image`)
 *     can be reused, by running `docker image inspect`. A cached hit is the
 *     common case across reloads — we do not rebuild on every EnvSetup run.
 *   - Force a rebuild when the Dockerfile's mtime is newer than
 *     `state.updated_at`. This catches the "user edited the Dockerfile and
 *     re-ran EnvSetup" case without requiring an explicit flag.
 *   - When a build is required, run `docker build -t <tag> -f <dockerfile>
 *     .` from the challenge folder and capture stdout+stderr to a log file
 *     under `.omp/logs/`.
 *   - Translate spawn-level failures into a top-level
 *     {@link EnvSetupError} with `kind: "docker-not-available"` so the
 *     pipeline can fail loudly with an actionable message instead of a
 *     bare `ENOENT`.
 */

import { statSync, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"
import type { ChallengeState } from "../state/challenge-state"
import { resolveLogsDir } from "../state/layout"
import type { DockerRunner } from "./docker-runner"
import { EnvSetupError } from "./envsetup-error"

export interface DockerBuildResult {
  /** The tag now in use, whether built fresh or reused from cache. */
  imageTag: string
  /** True if `docker build` was skipped (existing image reused). */
  cached: boolean
  /**
   * Absolute path to the captured build log. `undefined` when `cached`
   * is `true` (no log was produced because no build ran).
   */
  buildLogPath?: string
}

export interface DockerBuildOptions {
  /** Override the current time, used for deterministic log filenames. */
  now?: Date
  /**
   * Override the image tag instead of computing `omp-<binary_sha8>` from
   * state. Used by `omp_setup_docker_build` (T04) so the agent or operator
   * can supply a meaningful image name (e.g. `"afterimage"`, `"kaleido"`,
   * `"omp/pwno-mcp:dev"`) rather than the sha-derived default. When
   * supplied, the `binary_sha256` invariant on `state` is relaxed — the
   * caller is responsible for tag uniqueness.
   */
  imageTagOverride?: string
  /**
   * Force a fresh `docker build` regardless of cache state. Used by
   * `omp_setup_docker_build` (T04) when the agent explicitly requests
   * rebuild (e.g. user said "rebuild from scratch"). Default false.
   */
  forceRebuild?: boolean
}

/**
 * Build (or skip-because-cached) the challenge's Docker image.
 *
 * @param state — the loaded ChallengeState. Must have `binary_sha256` set
 *                (a T03 invariant).
 * @throws EnvSetupError on `docker-not-available` or `docker-build-failed`.
 */
export function dockerBuildImage(
  state: ChallengeState,
  runner: DockerRunner,
  opts: DockerBuildOptions = {},
): DockerBuildResult {
  let imageTag: string
  if (opts.imageTagOverride !== undefined) {
    imageTag = opts.imageTagOverride
  } else {
    if (state.binary_sha256 === undefined) {
      throw new Error(
        "internal: dockerBuildImage requires state with binary_sha256 (T03 invariant) when no imageTagOverride is supplied",
      )
    }
    imageTag = `omp-${state.binary_sha256.slice(0, 8)}`
  }

  const dockerfilePath = state.dockerfile_path
  const buildContext = dirname(dockerfilePath)
  const now = opts.now ?? new Date()

  if (
    opts.forceRebuild !== true &&
    canReuseImage(state, imageTag, dockerfilePath, runner)
  ) {
    return { imageTag, cached: true }
  }

  const args = ["build", "-t", imageTag, "-f", dockerfilePath, buildContext]
  let result
  try {
    result = runner.run(args, { cwd: buildContext })
  } catch (err) {
    throw translateSpawnError(err, state.challenge_dir)
  }

  const buildLogPath = writeBuildLog(state, result.stdout, result.stderr, now)

  if (result.exitCode !== 0) {
    throw new EnvSetupError({
      kind: "docker-build-failed",
      challengeDir: state.challenge_dir,
      message: `docker build failed with exit code ${result.exitCode}. See ${buildLogPath} for full output.`,
      exitCode: result.exitCode,
      imageTag,
      dockerfilePath,
      buildLogPath,
    })
  }

  return { imageTag, cached: false, buildLogPath }
}

/**
 * True iff (a) `state.docker_image` matches the tag we would build now,
 * (b) `docker image inspect` confirms the image is still in the local
 * registry, and (c) the Dockerfile has not been modified since the state
 * was last updated.
 */
function canReuseImage(
  state: ChallengeState,
  imageTag: string,
  dockerfilePath: string,
  runner: DockerRunner,
): boolean {
  if (state.docker_image !== imageTag) {
    return false
  }
  if (isDockerfileNewerThanState(state, dockerfilePath)) {
    return false
  }
  let inspect
  try {
    inspect = runner.run(["image", "inspect", imageTag])
  } catch {
    // Spawn error here is unusual — we'll re-encounter it on `docker build`
    // and translate it there. For inspect, treat as cache miss.
    return false
  }
  return inspect.exitCode === 0
}

function isDockerfileNewerThanState(
  state: ChallengeState,
  dockerfilePath: string,
): boolean {
  let dockerfileMtime: Date
  try {
    dockerfileMtime = statSync(dockerfilePath).mtime
  } catch {
    // If the Dockerfile is unreadable now, we can't compare — let the build
    // step handle the actual error.
    return false
  }
  const stateUpdatedAt = new Date(state.updated_at).getTime()
  // Allow 1s of slack to absorb filesystem mtime resolution differences.
  return dockerfileMtime.getTime() > stateUpdatedAt + 1000
}

function writeBuildLog(
  state: ChallengeState,
  stdout: Buffer,
  stderr: Buffer,
  now: Date,
): string {
  const logsDir = resolveLogsDir(state.challenge_dir)
  const safeTimestamp = now.toISOString().replace(/[:]/gu, "-")
  const logPath = join(logsDir, `docker-build-${safeTimestamp}.log`)
  const body = Buffer.concat([
    Buffer.from("=== stdout ===\n", "utf-8"),
    stdout,
    Buffer.from("\n=== stderr ===\n", "utf-8"),
    stderr,
    Buffer.from("\n", "utf-8"),
  ])
  writeFileSync(logPath, body)
  return logPath
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
