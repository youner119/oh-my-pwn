import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { initializeOmpDir } from "../state/io"
import { resolveLogsDir } from "../state/layout"
import { dockerBuildImage } from "./docker-build"
import { EnvSetupError } from "./envsetup-error"
import { FakeDockerRunner, dockerEnoentError } from "./fake-docker-runner"

function makeChallengeDir(label: string): string {
  const dir = join(
    tmpdir(),
    `omp-docker-build-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  )
  mkdirSync(dir, { recursive: true })
  return dir
}

/** Bootstrap `.omp/` (for the log dir) and a Dockerfile; return its path. */
function setupChallenge(dir: string): string {
  initializeOmpDir(dir)
  const dockerfilePath = join(dir, "Dockerfile")
  writeFileSync(dockerfilePath, "FROM alpine\n")
  return dockerfilePath
}

describe("dockerBuildImage", () => {
  let dir: string

  beforeEach(() => {
    dir = makeChallengeDir("db")
  })

  afterEach(() => {
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  describe("build", () => {
    test("invokes `docker build` with the supplied tag and writes a log", () => {
      const dockerfilePath = setupChallenge(dir)
      const runner = new FakeDockerRunner((call) => {
        if (call.args[0] === "build") {
          return { exitCode: 0, stdout: "Successfully tagged afterimage\n" }
        }
        throw new Error(`unexpected call: ${call.args.join(" ")}`)
      })

      const result = dockerBuildImage(
        {
          challengeDir: dir,
          dockerfilePath,
          imageTag: "afterimage",
          now: new Date("2026-04-11T12:00:00.000Z"),
        },
        runner,
      )

      expect(result.imageTag).toBe("afterimage")
      expect(existsSync(result.buildLogPath)).toBe(true)

      const log = readFileSync(result.buildLogPath, "utf-8")
      expect(log).toContain("=== stdout ===")
      expect(log).toContain("Successfully tagged")
      expect(log).toContain("=== stderr ===")

      // docker build -t <tag> -f <dockerfile> <context>
      const buildCall = runner.calls.find((c) => c.args[0] === "build")!
      expect(buildCall.args).toEqual([
        "build",
        "-t",
        "afterimage",
        "-f",
        dockerfilePath,
        dir,
      ])
      expect(buildCall.opts.cwd).toBe(dir)
    })

    test("captures stdout AND stderr in the log file", () => {
      const dockerfilePath = setupChallenge(dir)
      const runner = new FakeDockerRunner(() => ({
        exitCode: 0,
        stdout: "Step 1/3 : FROM alpine\n",
        stderr: "warning: skipping ...\n",
      }))

      const result = dockerBuildImage(
        { challengeDir: dir, dockerfilePath, imageTag: "t" },
        runner,
      )
      const log = readFileSync(result.buildLogPath, "utf-8")
      expect(log).toContain("Step 1/3")
      expect(log).toContain("warning: skipping")
    })

    test("forceRebuild adds --no-cache; default does not", () => {
      const dockerfilePath = setupChallenge(dir)

      const forcedRunner = new FakeDockerRunner(() => ({ exitCode: 0 }))
      dockerBuildImage(
        { challengeDir: dir, dockerfilePath, imageTag: "t", forceRebuild: true },
        forcedRunner,
      )
      expect(forcedRunner.calls.find((c) => c.args[0] === "build")!.args).toContain(
        "--no-cache",
      )

      const plainRunner = new FakeDockerRunner(() => ({ exitCode: 0 }))
      dockerBuildImage(
        { challengeDir: dir, dockerfilePath, imageTag: "t" },
        plainRunner,
      )
      expect(
        plainRunner.calls.find((c) => c.args[0] === "build")!.args,
      ).not.toContain("--no-cache")
    })
  })

  describe("error translation", () => {
    test("docker-not-available on ENOENT spawn error", () => {
      const dockerfilePath = setupChallenge(dir)
      const runner = new FakeDockerRunner(() => ({
        exitCode: 0,
        throwError: dockerEnoentError(),
      }))

      try {
        dockerBuildImage({ challengeDir: dir, dockerfilePath, imageTag: "t" }, runner)
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(EnvSetupError)
        const e = err as EnvSetupError
        expect(e.kind).toBe("docker-not-available")
        if (e.detail.kind === "docker-not-available") {
          expect(e.detail.code).toBe("ENOENT")
        }
      }
    })

    test("docker-build-failed on non-zero exit, log path attached", () => {
      const dockerfilePath = setupChallenge(dir)
      const runner = new FakeDockerRunner((call) => {
        if (call.args[0] === "build") {
          return {
            exitCode: 2,
            stdout: "Step 1/3 : FROM alpine\n",
            stderr: "ERROR: failed to fetch\n",
          }
        }
        throw new Error(`unexpected call: ${call.args.join(" ")}`)
      })

      try {
        dockerBuildImage(
          { challengeDir: dir, dockerfilePath, imageTag: "afterimage" },
          runner,
        )
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(EnvSetupError)
        const e = err as EnvSetupError
        expect(e.kind).toBe("docker-build-failed")
        if (e.detail.kind === "docker-build-failed") {
          expect(e.detail.exitCode).toBe(2)
          expect(e.detail.imageTag).toBe("afterimage")
          expect(existsSync(e.detail.buildLogPath)).toBe(true)
          // Log written even for failed builds — critical for debugging.
          const log = readFileSync(e.detail.buildLogPath, "utf-8")
          expect(log).toContain("ERROR: failed to fetch")
        }
      }
    })
  })

  describe("logs directory wiring", () => {
    test("log file lands inside .omp/logs/", () => {
      const dockerfilePath = setupChallenge(dir)
      const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))

      const result = dockerBuildImage(
        { challengeDir: dir, dockerfilePath, imageTag: "t" },
        runner,
      )

      expect(result.buildLogPath.startsWith(resolveLogsDir(dir))).toBe(true)
    })
  })
})
