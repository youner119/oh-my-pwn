import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { extractLibcAndLd } from "./docker-extract"
import { EnvSetupError } from "./envsetup-error"
import { FakeDockerRunner, dockerEnoentError } from "./fake-docker-runner"
import {
  buildElfFixture,
  TEST_PT_INTERP,
  TEST_PT_LOAD,
} from "./elf-test-fixtures"

const FAKE_CONTAINER_ID = "abc123def456"

function makeChallengeDir(label: string): string {
  const dir = join(
    tmpdir(),
    `omp-extract-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  )
  mkdirSync(dir, { recursive: true })
  return dir
}

interface ExtractInputs {
  challengeDir: string
  binaryPath: string
  artifactsDir: string
}

function setupChallenge(label: string, opts: { dynamic: boolean }): ExtractInputs {
  const challengeDir = makeChallengeDir(label)
  const artifactsDir = join(challengeDir, ".omp", "artifacts")
  mkdirSync(artifactsDir, { recursive: true })

  // Synthesize a binary fixture matching the static/dynamic intent.
  const programHeaders = opts.dynamic
    ? [{ type: TEST_PT_INTERP }]
    : [{ type: TEST_PT_LOAD }]
  const elf = buildElfFixture({ type: "exec", programHeaders })
  const binaryPath = join(challengeDir, "chall")
  writeFileSync(binaryPath, elf)
  return { challengeDir, binaryPath, artifactsDir }
}

describe("extractLibcAndLd", () => {
  let inputs: ExtractInputs

  afterEach(() => {
    if (inputs !== undefined && existsSync(inputs.challengeDir)) {
      rmSync(inputs.challengeDir, { recursive: true, force: true })
    }
  })

  describe("happy path", () => {
    beforeEach(() => {
      inputs = setupChallenge("happy", { dynamic: true })
    })

    test("copies libc and ld from the first matching candidate paths", () => {
      const fakeLibcContent = "GNU C Library 2.31\n".repeat(100)
      const fakeLdContent = "ELF interpreter bytes\n".repeat(50)

      const runner = new FakeDockerRunner((call) => {
        if (call.args[0] === "create") {
          return { exitCode: 0, stdout: `${FAKE_CONTAINER_ID}\n` }
        }
        if (call.args[0] === "cp") {
          // call.args = ["cp", "-L", "<container>:<src>", "<dest>"]
          const src = call.args[2]!
          const dest = call.args[3]!
          if (src.includes("/lib/x86_64-linux-gnu/libc.so.6")) {
            writeFileSync(dest, fakeLibcContent)
            return { exitCode: 0 }
          }
          if (src.includes("/lib64/ld-linux-x86-64.so.2")) {
            writeFileSync(dest, fakeLdContent)
            return { exitCode: 0 }
          }
          // Anything else: not present.
          return { exitCode: 1, stderr: "no such file\n" }
        }
        if (call.args[0] === "rm") {
          return { exitCode: 0 }
        }
        throw new Error(`unexpected call: ${call.args.join(" ")}`)
      })

      const result = extractLibcAndLd(
        {
          imageTag: "omp-test",
          binaryPath: inputs.binaryPath,
          artifactsDir: inputs.artifactsDir,
          challengeDir: inputs.challengeDir,
        },
        runner,
      )

      expect(result.staticLinked).toBe(false)
      if (result.staticLinked === false) {
        expect(result.libcImagePath).toBe("/lib/x86_64-linux-gnu/libc.so.6")
        expect(result.libcPath).toBe(join(inputs.artifactsDir, "libc.so.6"))
        expect(readFileSync(result.libcPath, "utf-8")).toBe(fakeLibcContent)
        expect(result.ldImagePath).toBe("/lib64/ld-linux-x86-64.so.2")
        expect(result.ldPath).toBe(
          join(inputs.artifactsDir, "ld-linux-x86-64.so.2"),
        )
      }

      // Verify cleanup happened.
      const rmCall = runner.calls.find((c) => c.args[0] === "rm")
      expect(rmCall).toBeDefined()
      expect(rmCall!.args).toEqual(["rm", "-f", FAKE_CONTAINER_ID])
    })

    test("falls back to /lib64/libc.so.6 when the multiarch path is missing", () => {
      const runner = new FakeDockerRunner((call) => {
        if (call.args[0] === "create") {
          return { exitCode: 0, stdout: `${FAKE_CONTAINER_ID}\n` }
        }
        if (call.args[0] === "cp") {
          const src = call.args[2]!
          const dest = call.args[3]!
          if (src.includes("/lib64/libc.so.6")) {
            writeFileSync(dest, "fake libc bytes\n")
            return { exitCode: 0 }
          }
          return { exitCode: 1 }
        }
        return { exitCode: 0 }
      })

      const result = extractLibcAndLd(
        {
          imageTag: "omp-test",
          binaryPath: inputs.binaryPath,
          artifactsDir: inputs.artifactsDir,
          challengeDir: inputs.challengeDir,
        },
        runner,
      )

      if (result.staticLinked === false) {
        expect(result.libcImagePath).toBe("/lib64/libc.so.6")
      }
    })

    test("returns ld undefined when libc is found but ld is not", () => {
      const runner = new FakeDockerRunner((call) => {
        if (call.args[0] === "create") {
          return { exitCode: 0, stdout: `${FAKE_CONTAINER_ID}\n` }
        }
        if (call.args[0] === "cp") {
          const src = call.args[2]!
          const dest = call.args[3]!
          if (src.includes("libc.so.6")) {
            writeFileSync(dest, "fake libc\n")
            return { exitCode: 0 }
          }
          return { exitCode: 1 }
        }
        return { exitCode: 0 }
      })

      const result = extractLibcAndLd(
        {
          imageTag: "omp-test",
          binaryPath: inputs.binaryPath,
          artifactsDir: inputs.artifactsDir,
          challengeDir: inputs.challengeDir,
        },
        runner,
      )

      if (result.staticLinked === false) {
        expect(result.libcPath).toBeDefined()
        expect(result.ldPath).toBeUndefined()
      }
    })
  })

  describe("static-linked binary", () => {
    beforeEach(() => {
      inputs = setupChallenge("static", { dynamic: false })
    })

    test("returns staticLinked: true when libc is missing AND binary has no PT_INTERP", () => {
      const runner = new FakeDockerRunner((call) => {
        if (call.args[0] === "create") {
          return { exitCode: 0, stdout: `${FAKE_CONTAINER_ID}\n` }
        }
        if (call.args[0] === "cp") {
          return { exitCode: 1, stderr: "not present\n" }
        }
        if (call.args[0] === "rm") {
          return { exitCode: 0 }
        }
        throw new Error(`unexpected: ${call.args.join(" ")}`)
      })

      const result = extractLibcAndLd(
        {
          imageTag: "omp-test",
          binaryPath: inputs.binaryPath,
          artifactsDir: inputs.artifactsDir,
          challengeDir: inputs.challengeDir,
        },
        runner,
      )

      expect(result.staticLinked).toBe(true)
      // Cleanup still happened.
      expect(runner.calls.find((c) => c.args[0] === "rm")).toBeDefined()
    })
  })

  describe("libc-not-found error", () => {
    beforeEach(() => {
      inputs = setupChallenge("nolibc", { dynamic: true })
    })

    test("throws with full candidate list when binary is dynamic but image has no libc", () => {
      const runner = new FakeDockerRunner((call) => {
        if (call.args[0] === "create") {
          return { exitCode: 0, stdout: `${FAKE_CONTAINER_ID}\n` }
        }
        if (call.args[0] === "cp") {
          return { exitCode: 1, stderr: "not present\n" }
        }
        if (call.args[0] === "run") {
          // Listing probe — return a fake `ls` output.
          return {
            exitCode: 0,
            stdout: "drwxr-xr-x ... /lib\ntotal 0\n-rwxr-xr-x ... busybox\n",
          }
        }
        if (call.args[0] === "rm") {
          return { exitCode: 0 }
        }
        throw new Error(`unexpected: ${call.args.join(" ")}`)
      })

      try {
        extractLibcAndLd(
          {
            imageTag: "omp-test",
            binaryPath: inputs.binaryPath,
            artifactsDir: inputs.artifactsDir,
            challengeDir: inputs.challengeDir,
          },
          runner,
        )
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(EnvSetupError)
        const e = err as EnvSetupError
        expect(e.kind).toBe("libc-not-found")
        if (e.detail.kind === "libc-not-found") {
          expect(e.detail.candidatesTried.length).toBeGreaterThan(0)
          expect(e.detail.candidatesTried).toContain(
            "/lib/x86_64-linux-gnu/libc.so.6",
          )
          expect(e.detail.imageListing).toBeDefined()
          expect(e.detail.imageListing!.length).toBeGreaterThan(0)
        }
      }

      // Cleanup must have run despite the throw.
      expect(runner.calls.find((c) => c.args[0] === "rm")).toBeDefined()
    })
  })

  describe("docker-not-available", () => {
    beforeEach(() => {
      inputs = setupChallenge("noenv", { dynamic: true })
    })

    test("translates ENOENT on `docker create` to docker-not-available", () => {
      const runner = new FakeDockerRunner(() => ({
        exitCode: 0,
        throwError: dockerEnoentError(),
      }))

      try {
        extractLibcAndLd(
          {
            imageTag: "omp-test",
            binaryPath: inputs.binaryPath,
            artifactsDir: inputs.artifactsDir,
            challengeDir: inputs.challengeDir,
          },
          runner,
        )
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(EnvSetupError)
        expect((err as EnvSetupError).kind).toBe("docker-not-available")
      }
    })
  })

  describe("create-failed", () => {
    beforeEach(() => {
      inputs = setupChallenge("createfail", { dynamic: true })
    })

    test("throws extraction-failed when docker create returns non-zero", () => {
      const runner = new FakeDockerRunner((call) => {
        if (call.args[0] === "create") {
          return { exitCode: 125, stderr: "Unable to find image\n" }
        }
        return { exitCode: 0 }
      })

      try {
        extractLibcAndLd(
          {
            imageTag: "omp-test",
            binaryPath: inputs.binaryPath,
            artifactsDir: inputs.artifactsDir,
            challengeDir: inputs.challengeDir,
          },
          runner,
        )
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(EnvSetupError)
        const e = err as EnvSetupError
        expect(e.kind).toBe("extraction-failed")
        if (e.detail.kind === "extraction-failed") {
          expect(e.detail.exitCode).toBe(125)
          expect(e.detail.stderr).toContain("Unable to find image")
        }
      }
    })
  })
})
