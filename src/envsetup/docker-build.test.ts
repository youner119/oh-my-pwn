import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { initializeOmpDir, saveChallengeState } from "../state/io"
import { resolveLogsDir } from "../state/layout"
import type { ChallengeState } from "../state/challenge-state"
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

function seedState(challengeDir: string): ChallengeState {
  // Seed a real .omp/ via the loader-style minimal init, then stamp the input
  // identity fields the way omp-setup Phase 0 (Detect) would after the
  // contract-load-detect-split change (`.omc/specs/contract-load-detect-split.md`).
  const dockerfilePath = join(challengeDir, "Dockerfile")
  writeFileSync(dockerfilePath, "FROM alpine\n")
  const binaryPath = join(challengeDir, "chall")
  writeFileSync(binaryPath, Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
  const initial = initializeOmpDir({ challenge_dir: challengeDir })
  return saveChallengeState({
    ...initial,
    binary_input_path: binaryPath,
    binary_input_sha256:
      "abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
    dockerfile_path: dockerfilePath,
    binary_sha256:
      "abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
  })
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

  describe("fresh build", () => {
    test("invokes `docker build` with the expected tag and writes a log", () => {
      const state = seedState(dir)
      const runner = new FakeDockerRunner((call) => {
        if (call.args[0] === "build") {
          return { exitCode: 0, stdout: "Successfully tagged omp-abc123de\n" }
        }
        throw new Error(`unexpected call: ${call.args.join(" ")}`)
      })

      const result = dockerBuildImage(state, runner, {
        now: new Date("2026-04-11T12:00:00.000Z"),
      })

      expect(result.imageTag).toBe("omp-abc123de")
      expect(result.cached).toBe(false)
      expect(result.buildLogPath).toBeDefined()
      expect(existsSync(result.buildLogPath!)).toBe(true)

      const log = readFileSync(result.buildLogPath!, "utf-8")
      expect(log).toContain("=== stdout ===")
      expect(log).toContain("Successfully tagged")
      expect(log).toContain("=== stderr ===")

      // Verify the build invocation shape: docker build -t <tag> -f <dockerfile> <context>
      const buildCall = runner.calls.find((c) => c.args[0] === "build")!
      expect(buildCall.args).toEqual([
        "build",
        "-t",
        "omp-abc123de",
        "-f",
        join(dir, "Dockerfile"),
        dir,
      ])
      expect(buildCall.opts.cwd).toBe(dir)
    })

    test("captures stdout AND stderr in the log file", () => {
      const state = seedState(dir)
      const runner = new FakeDockerRunner(() => ({
        exitCode: 0,
        stdout: "Step 1/3 : FROM alpine\n",
        stderr: "warning: skipping ...\n",
      }))

      const result = dockerBuildImage(state, runner)
      const log = readFileSync(result.buildLogPath!, "utf-8")
      expect(log).toContain("Step 1/3")
      expect(log).toContain("warning: skipping")
    })
  })

  describe("cache hit", () => {
    test("skips build when state.docker_image matches and inspect succeeds", () => {
      const state = saveChallengeState({
        ...seedState(dir),
        docker_image: "omp-abc123de",
      })
      const runner = new FakeDockerRunner((call) => {
        if (call.args[0] === "image" && call.args[1] === "inspect") {
          return { exitCode: 0, stdout: "[{...}]\n" }
        }
        throw new Error(`unexpected call: ${call.args.join(" ")}`)
      })

      const result = dockerBuildImage(state, runner)

      expect(result.cached).toBe(true)
      expect(result.imageTag).toBe("omp-abc123de")
      expect(result.buildLogPath).toBeUndefined()
      // Only the inspect call should have happened.
      expect(runner.calls.length).toBe(1)
    })

    test("rebuilds when state.docker_image is set but inspect returns non-zero", () => {
      const state = saveChallengeState({
        ...seedState(dir),
        docker_image: "omp-abc123de",
      })
      const runner = new FakeDockerRunner((call) => {
        if (call.args[0] === "image" && call.args[1] === "inspect") {
          return { exitCode: 1, stderr: "no such image\n" }
        }
        if (call.args[0] === "build") {
          return { exitCode: 0 }
        }
        throw new Error(`unexpected call: ${call.args.join(" ")}`)
      })

      const result = dockerBuildImage(state, runner)
      expect(result.cached).toBe(false)
    })

    test("rebuilds when Dockerfile mtime is newer than state.updated_at", () => {
      const state = saveChallengeState({
        ...seedState(dir),
        docker_image: "omp-abc123de",
      })
      // Touch the Dockerfile so its mtime is at least 2s after state.updated_at.
      const dockerfilePath = state.dockerfile_path
      const futureMtime = new Date(Date.now() + 60_000)
      writeFileSync(dockerfilePath, "FROM alpine\nRUN echo updated\n")
      const { utimesSync } = require("node:fs") as typeof import("node:fs")
      utimesSync(dockerfilePath, futureMtime, futureMtime)

      let inspectCalled = false
      const runner = new FakeDockerRunner((call) => {
        if (call.args[0] === "image" && call.args[1] === "inspect") {
          inspectCalled = true
          return { exitCode: 0, stdout: "[{...}]\n" }
        }
        if (call.args[0] === "build") {
          return { exitCode: 0 }
        }
        throw new Error(`unexpected call: ${call.args.join(" ")}`)
      })

      const result = dockerBuildImage(state, runner)
      expect(result.cached).toBe(false)
      // The mtime check should short-circuit before we ever call inspect.
      expect(inspectCalled).toBe(false)
    })
  })

  describe("error translation", () => {
    test("docker-not-available on ENOENT spawn error", () => {
      const state = seedState(dir)
      const runner = new FakeDockerRunner(() => ({
        exitCode: 0,
        throwError: dockerEnoentError(),
      }))

      try {
        dockerBuildImage(state, runner)
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
      const state = seedState(dir)
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
        dockerBuildImage(state, runner)
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(EnvSetupError)
        const e = err as EnvSetupError
        expect(e.kind).toBe("docker-build-failed")
        if (e.detail.kind === "docker-build-failed") {
          expect(e.detail.exitCode).toBe(2)
          expect(e.detail.imageTag).toBe("omp-abc123de")
          expect(existsSync(e.detail.buildLogPath)).toBe(true)
          // Log was still written for failed builds — critical for debugging.
          const log = readFileSync(e.detail.buildLogPath, "utf-8")
          expect(log).toContain("ERROR: failed to fetch")
        }
      }
    })
  })

  describe("invariant", () => {
    test("throws a programmer-error when neither input nor patched sha is set", () => {
      const state = seedState(dir)
      // Both shas absent — no way to derive `omp-<sha8>`. The default tag
      // path prefers `binary_input_sha256` (loader invariant) and falls
      // back to `binary_sha256` (legacy patched-copy sha); throwing only
      // when both are missing keeps `omp_setup_docker_build` (which
      // supplies its own override) and legacy `runEnvSetup` both working.
      const broken: ChallengeState = {
        ...state,
        binary_sha256: undefined,
        binary_input_sha256: undefined,
      }
      const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))

      try {
        dockerBuildImage(broken, runner)
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(Error)
        expect((err as Error).message).toContain("binary_input_sha256")
      }
    })
  })

  describe("logs directory wiring", () => {
    test("log file lands inside .omp/logs/", () => {
      const state = seedState(dir)
      const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))

      const result = dockerBuildImage(state, runner)

      const logsDir = resolveLogsDir(dir)
      expect(result.buildLogPath!.startsWith(logsDir)).toBe(true)
    })
  })

  describe("imageTagOverride (T04 — omp_setup_docker_build)", () => {
    test("uses the supplied tag instead of computing omp-<sha8>", () => {
      const state = seedState(dir)
      const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))

      const result = dockerBuildImage(state, runner, {
        imageTagOverride: "afterimage",
      })

      expect(result.imageTag).toBe("afterimage")
      // The actual build command should have used the override too.
      const buildCall = runner.calls.find((c) => c.args[0] === "build")
      expect(buildCall?.args).toContain("afterimage")
      // sha-derived default must NOT appear.
      expect(buildCall?.args).not.toContain("omp-abc123de")
    })

    test("relaxes binary_sha256 invariant when override is supplied", () => {
      // T04 use case: setup agent calls Phase 1 docker_build before any
      // patched binary exists (binary_sha256 is the patched copy's hash).
      // Only binary_input_sha256 is set at this point. The override path
      // must NOT require state.binary_sha256.
      const state = seedState(dir)
      const noSha: ChallengeState = { ...state, binary_sha256: undefined }
      const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))

      const result = dockerBuildImage(noSha, runner, {
        imageTagOverride: "kaleido",
      })

      expect(result.imageTag).toBe("kaleido")
      expect(result.cached).toBe(false)
    })

    test("cache reuse still works with override (state.docker_image == override)", () => {
      const initial = seedState(dir)
      // Pretend a previous run with the same override tag finished.
      const cachedState = saveChallengeState({
        ...initial,
        docker_image: "afterimage",
      })
      const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))

      const result = dockerBuildImage(cachedState, runner, {
        imageTagOverride: "afterimage",
      })

      expect(result.imageTag).toBe("afterimage")
      expect(result.cached).toBe(true)
      // No build should have been invoked.
      const buildCall = runner.calls.find((c) => c.args[0] === "build")
      expect(buildCall).toBeUndefined()
    })

    test("cache miss when override differs from previously recorded image", () => {
      const initial = seedState(dir)
      const cachedState = saveChallengeState({
        ...initial,
        docker_image: "old-tag",
      })
      const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))

      const result = dockerBuildImage(cachedState, runner, {
        imageTagOverride: "new-tag",
      })

      expect(result.imageTag).toBe("new-tag")
      expect(result.cached).toBe(false)
    })
  })
})
