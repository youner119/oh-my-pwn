import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { createHash } from "node:crypto"
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { EnvSetupError } from "./envsetup-error"
import { patchBinaryInterpreter, type SpawnFn } from "./patch-elf"

const ORIGINAL_BYTES = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0xaa, 0xbb])

function makeTmp(label: string): {
  dir: string
  binaryPath: string
  backupPath: string
  ldPath: string
  libcDir: string
} {
  const dir = join(
    tmpdir(),
    `omp-patch-elf-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  )
  mkdirSync(dir, { recursive: true })
  const artifactsDir = join(dir, ".omp", "artifacts")
  mkdirSync(artifactsDir, { recursive: true })
  const binaryPath = join(dir, "chall")
  writeFileSync(binaryPath, ORIGINAL_BYTES)
  const ldPath = join(artifactsDir, "ld-linux-x86-64.so.2")
  writeFileSync(ldPath, "fake ld\n")
  writeFileSync(join(artifactsDir, "libc.so.6"), "fake libc\n")
  return {
    dir,
    binaryPath,
    backupPath: join(artifactsDir, "chall.orig"),
    ldPath,
    libcDir: artifactsDir,
  }
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex")
}

describe("patchBinaryInterpreter", () => {
  let env: ReturnType<typeof makeTmp>

  beforeEach(() => {
    env = makeTmp("p")
  })

  afterEach(() => {
    if (existsSync(env.dir)) {
      rmSync(env.dir, { recursive: true, force: true })
    }
  })

  describe("happy path", () => {
    test("creates the backup, runs patchelf, returns the new sha", () => {
      const calls: Array<{ cmd: string; args: readonly string[] }> = []
      const fakeSpawn: SpawnFn = (cmd, args) => {
        calls.push({ cmd, args })
        // Simulate patchelf rewriting the binary in place.
        writeFileSync(env.binaryPath, Buffer.concat([ORIGINAL_BYTES, Buffer.from("PATCHED")]))
        return { exitCode: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }
      }

      const result = patchBinaryInterpreter(
        {
          binaryPath: env.binaryPath,
          backupPath: env.backupPath,
          interpreterPath: env.ldPath,
          libcDir: env.libcDir,
          challengeDir: env.dir,
        },
        { spawn: fakeSpawn },
      )

      expect(result.backupCreated).toBe(true)
      expect(existsSync(env.backupPath)).toBe(true)
      expect(readFileSync(env.backupPath)).toEqual(ORIGINAL_BYTES)
      expect(result.originalSha256).toBe(sha256(ORIGINAL_BYTES))

      // patchelf was called with the right args.
      expect(calls.length).toBe(1)
      expect(calls[0]!.cmd).toBe("patchelf")
      expect(calls[0]!.args).toEqual([
        "--set-interpreter",
        env.ldPath,
        "--set-rpath",
        env.libcDir,
        env.binaryPath,
      ])

      // Patched sha differs from original.
      expect(result.patchedSha256).not.toBe(result.originalSha256)
      expect(result.patchedSha256).toBe(
        sha256(Buffer.concat([ORIGINAL_BYTES, Buffer.from("PATCHED")])),
      )
    })
  })

  describe("idempotent re-patch", () => {
    test("on re-run, restores from backup before patching (binary always patches a fresh original)", () => {
      // Pre-seed: a backup already exists from a previous run, AND the
      // binary on disk is currently a stale patched version.
      writeFileSync(env.backupPath, ORIGINAL_BYTES)
      writeFileSync(
        env.binaryPath,
        Buffer.concat([ORIGINAL_BYTES, Buffer.from("STALE-PATCH")]),
      )

      let bytesSeenByPatchelf: Buffer | undefined
      const fakeSpawn: SpawnFn = () => {
        bytesSeenByPatchelf = readFileSync(env.binaryPath)
        // Simulate a fresh patch.
        writeFileSync(
          env.binaryPath,
          Buffer.concat([ORIGINAL_BYTES, Buffer.from("FRESH-PATCH")]),
        )
        return { exitCode: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }
      }

      const result = patchBinaryInterpreter(
        {
          binaryPath: env.binaryPath,
          backupPath: env.backupPath,
          interpreterPath: env.ldPath,
          libcDir: env.libcDir,
          challengeDir: env.dir,
        },
        { spawn: fakeSpawn },
      )

      expect(result.backupCreated).toBe(false) // backup already existed
      // Critical: patchelf saw the *restored original*, not the stale patch.
      expect(bytesSeenByPatchelf).toEqual(ORIGINAL_BYTES)
      // Final binary on disk is the FRESH patch (not the stale one).
      expect(readFileSync(env.binaryPath)).toEqual(
        Buffer.concat([ORIGINAL_BYTES, Buffer.from("FRESH-PATCH")]),
      )
    })
  })

  describe("error cases", () => {
    test("translates ENOENT spawn error to patchelf-not-available", () => {
      const enoent = Object.assign(new Error("spawnSync patchelf ENOENT"), {
        code: "ENOENT",
      })
      const fakeSpawn: SpawnFn = () => {
        throw enoent
      }

      try {
        patchBinaryInterpreter(
          {
            binaryPath: env.binaryPath,
            backupPath: env.backupPath,
            interpreterPath: env.ldPath,
            libcDir: env.libcDir,
            challengeDir: env.dir,
          },
          { spawn: fakeSpawn },
        )
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(EnvSetupError)
        const e = err as EnvSetupError
        expect(e.kind).toBe("patchelf-not-available")
        if (e.detail.kind === "patchelf-not-available") {
          expect(e.detail.code).toBe("ENOENT")
        }
      }
    })

    test("translates non-zero exit to patchelf-failed with stderr attached", () => {
      const fakeSpawn: SpawnFn = () => ({
        exitCode: 1,
        stdout: Buffer.alloc(0),
        stderr: Buffer.from("patchelf: cannot find section .interp\n", "utf-8"),
      })

      try {
        patchBinaryInterpreter(
          {
            binaryPath: env.binaryPath,
            backupPath: env.backupPath,
            interpreterPath: env.ldPath,
            libcDir: env.libcDir,
            challengeDir: env.dir,
          },
          { spawn: fakeSpawn },
        )
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(EnvSetupError)
        const e = err as EnvSetupError
        expect(e.kind).toBe("patchelf-failed")
        if (e.detail.kind === "patchelf-failed") {
          expect(e.detail.exitCode).toBe(1)
          expect(e.detail.stderr).toContain("cannot find section .interp")
          expect(e.detail.binaryPath).toBe(env.binaryPath)
        }
      }
    })

    test("backup is still created before patchelf is invoked (so even on patch failure, the original is preserved)", () => {
      const fakeSpawn: SpawnFn = () => ({
        exitCode: 1,
        stdout: Buffer.alloc(0),
        stderr: Buffer.from("oops\n", "utf-8"),
      })

      try {
        patchBinaryInterpreter(
          {
            binaryPath: env.binaryPath,
            backupPath: env.backupPath,
            interpreterPath: env.ldPath,
            libcDir: env.libcDir,
            challengeDir: env.dir,
          },
          { spawn: fakeSpawn },
        )
      } catch {
        // expected
      }

      expect(existsSync(env.backupPath)).toBe(true)
      expect(readFileSync(env.backupPath)).toEqual(ORIGINAL_BYTES)
    })
  })
})
