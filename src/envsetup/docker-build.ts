/**
 * `docker build` wrapper — a thin, stateless executor.
 *
 * Responsibilities:
 *
 *   - Run `docker build -t <tag> -f <dockerfile> <context>` from the
 *     challenge folder and capture stdout+stderr to a log file under
 *     `.omp/logs/`.
 *   - Pass `--no-cache` when `forceRebuild` is set.
 *   - Translate spawn-level failures into a top-level {@link EnvSetupError}
 *     with `kind: "docker-not-available"` so the pipeline can fail loudly
 *     with an actionable message instead of a bare `ENOENT`.
 *
 * No state coupling: the caller (the omp-setup agent, via
 * `omp_setup_docker_build`) supplies `challengeDir` / `dockerfilePath` /
 * `imageTag` directly — it found them in Phase 0 Detect and records the
 * result in the DB via `mcp__omp-db__patch_state` afterwards. We do not run
 * our own cache-reuse bookkeeping: docker's own layer cache already reuses
 * unchanged layers, and `forceRebuild` maps to `--no-cache`.
 */

import { writeFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { resolveLogsDir } from "../state/layout"
import type { DockerRunner } from "./docker-runner"
import { EnvSetupError } from "./envsetup-error"

export interface DockerBuildResult {
  /** The tag built. */
  imageTag: string
  /** Absolute path to the captured build log. */
  buildLogPath: string
}

export interface DockerBuildInput {
  /** Challenge folder (used for log path + error context). */
  challengeDir: string
  /** Absolute path to the Dockerfile to build. Build context is its dir. */
  dockerfilePath: string
  /** Image tag to apply (`docker build -t <imageTag>`). */
  imageTag: string
  /** Pass `--no-cache` to force a fresh build. Default false. */
  forceRebuild?: boolean
  /** Override the current time, used for deterministic log filenames. */
  now?: Date
}

/**
 * Build the challenge's Docker image. Stateless: everything it needs comes in
 * via {@link DockerBuildInput}.
 *
 * @throws EnvSetupError on `docker-not-available` or `docker-build-failed`.
 */
export function dockerBuildImage(
  input: DockerBuildInput,
  runner: DockerRunner,
): DockerBuildResult {
  const { challengeDir, dockerfilePath, imageTag } = input
  const buildContext = dirname(dockerfilePath)
  const now = input.now ?? new Date()

  const args = ["build", "-t", imageTag, "-f", dockerfilePath]
  if (input.forceRebuild === true) {
    args.push("--no-cache")
  }
  args.push(buildContext)

  let result
  try {
    result = runner.run(args, { cwd: buildContext })
  } catch (err) {
    throw translateSpawnError(err, challengeDir)
  }

  const buildLogPath = writeBuildLog(challengeDir, result.stdout, result.stderr, now)

  if (result.exitCode !== 0) {
    throw new EnvSetupError({
      kind: "docker-build-failed",
      challengeDir,
      message: `docker build failed with exit code ${result.exitCode}. See ${buildLogPath} for full output.`,
      exitCode: result.exitCode,
      imageTag,
      dockerfilePath,
      buildLogPath,
    })
  }

  return { imageTag, buildLogPath }
}

function writeBuildLog(
  challengeDir: string,
  stdout: Buffer,
  stderr: Buffer,
  now: Date,
): string {
  const logsDir = resolveLogsDir(challengeDir)
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
