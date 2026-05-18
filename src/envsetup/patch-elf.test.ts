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
import {
  patchBinaryInterpreter,
  patchElf,
  type SpawnFn,
} from "./patch-elf"

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

  /* ── patchElf (T07 generic) ─────────────────────────────────────────── */

  describe("patchElf (omp_setup_patch_elf core)", () => {
    let env: ReturnType<typeof makeTmp>

    beforeEach(() => {
      env = makeTmp("patchElf")
    })
    afterEach(() => {
      rmSync(env.dir, { recursive: true, force: true })
    })

    test("binary case: copies src → dst and runs patchelf with interp + replacements", () => {
      const dst = join(env.libcDir, "prob")
      const seenArgs: readonly string[][] = []
      const fakeSpawn: SpawnFn = (cmd, args) => {
        seenArgs.push(Array.from(args))
        // Simulate patchelf modifying the dst byte (any change triggers
        // new sha).
        const orig = readFileSync(dst)
        writeFileSync(dst, Buffer.concat([orig, Buffer.from([0x99])]))
        return { exitCode: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }
      }

      const result = patchElf(
        {
          srcPath: env.binaryPath,
          dstPath: dst,
          interpreter: env.ldPath,
          replacements: {
            "libc.so.6": join(env.libcDir, "libc.so.6"),
            "libm.so.6": join(env.libcDir, "libm.so.6"),
          },
        },
        { spawn: fakeSpawn },
      )

      // src untouched
      expect(readFileSync(env.binaryPath)).toEqual(ORIGINAL_BYTES)
      // dst exists and differs from src (patchelf appended 0x99)
      expect(existsSync(dst)).toBe(true)
      expect(readFileSync(dst).length).toBeGreaterThan(ORIGINAL_BYTES.length)
      // patchelf args contain --set-interpreter + 2× --replace-needed
      expect(seenArgs[0]).toContain("--set-interpreter")
      expect(seenArgs[0]).toContain(env.ldPath)
      const replaceCount = seenArgs[0]!.filter(
        (a) => a === "--replace-needed",
      ).length
      expect(replaceCount).toBe(2)
      expect(seenArgs[0]).toContain("libc.so.6")
      expect(seenArgs[0]).toContain("libm.so.6")
      // --set-rpath must NOT appear (D3 — replace-needed instead)
      expect(seenArgs[0]).not.toContain("--set-rpath")

      // sha bookkeeping
      expect(result.invokedPatchelf).toBe(true)
      expect(result.patchedPath).toBe(dst)
      expect(result.originalSha256).toBe(
        createHash("sha256").update(ORIGINAL_BYTES).digest("hex"),
      )
      expect(result.patchedSha256).not.toBe(result.originalSha256)
    })

    test("library case: in-place patch (no dstPath) with replacements only", () => {
      // src plays the role of an extracted libm.so.6 already in artifacts.
      const seenArgs: string[][] = []
      const fakeSpawn: SpawnFn = (cmd, args) => {
        seenArgs.push(Array.from(args))
        const orig = readFileSync(env.binaryPath)
        writeFileSync(env.binaryPath, Buffer.concat([orig, Buffer.from([0x42])]))
        return { exitCode: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }
      }

      const result = patchElf(
        {
          srcPath: env.binaryPath,
          replacements: {
            "libc.so.6": join(env.libcDir, "libc.so.6"),
          },
        },
        { spawn: fakeSpawn },
      )

      // No interpreter flag for library
      expect(seenArgs[0]).not.toContain("--set-interpreter")
      // Replace-needed present
      expect(seenArgs[0]).toContain("--replace-needed")
      expect(seenArgs[0]).toContain("libc.so.6")
      // In-place: target is src itself
      expect(result.patchedPath).toBe(env.binaryPath)
      // src was modified (no backup, no restore)
      expect(readFileSync(env.binaryPath).length).toBeGreaterThan(
        ORIGINAL_BYTES.length,
      )
      expect(result.originalSha256).not.toBe(result.patchedSha256)
    })

    test("no-op path: neither interpreter nor replacements → no spawn, sha matches", () => {
      const dst = join(env.libcDir, "copied")
      let spawnCalled = false
      const fakeSpawn: SpawnFn = () => {
        spawnCalled = true
        return { exitCode: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }
      }

      const result = patchElf(
        { srcPath: env.binaryPath, dstPath: dst },
        { spawn: fakeSpawn },
      )

      expect(spawnCalled).toBe(false)
      expect(result.invokedPatchelf).toBe(false)
      // Copy still happened.
      expect(existsSync(dst)).toBe(true)
      expect(readFileSync(dst)).toEqual(ORIGINAL_BYTES)
      // sha matches (no patch applied).
      expect(result.originalSha256).toBe(result.patchedSha256)
    })

    test("src is NEVER mutated when dstPath is supplied", () => {
      const dst = join(env.libcDir, "prob")
      const fakeSpawn: SpawnFn = () => {
        // Simulate: patchelf writes garbage all over dst.
        writeFileSync(dst, Buffer.from([0xff, 0xff, 0xff]))
        return { exitCode: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }
      }

      patchElf(
        {
          srcPath: env.binaryPath,
          dstPath: dst,
          interpreter: env.ldPath,
        },
        { spawn: fakeSpawn },
      )

      expect(readFileSync(env.binaryPath)).toEqual(ORIGINAL_BYTES)
    })

    test("parent dir of dstPath is auto-created", () => {
      const deepDst = join(env.libcDir, "nested", "subdir", "prob")
      const fakeSpawn: SpawnFn = () => ({
        exitCode: 0,
        stdout: Buffer.alloc(0),
        stderr: Buffer.alloc(0),
      })

      patchElf(
        {
          srcPath: env.binaryPath,
          dstPath: deepDst,
          interpreter: env.ldPath,
        },
        { spawn: fakeSpawn },
      )

      expect(existsSync(deepDst)).toBe(true)
    })

    test("patchelf failure → EnvSetupError(patchelf-failed) with target path", () => {
      const dst = join(env.libcDir, "prob")
      const fakeSpawn: SpawnFn = () => ({
        exitCode: 1,
        stdout: Buffer.alloc(0),
        stderr: Buffer.from("cannot find a free slot for a NOTE\n", "utf-8"),
      })

      try {
        patchElf(
          {
            srcPath: env.binaryPath,
            dstPath: dst,
            interpreter: env.ldPath,
          },
          { spawn: fakeSpawn },
        )
        throw new Error("expected EnvSetupError")
      } catch (err) {
        expect(err).toBeInstanceOf(EnvSetupError)
        const e = err as EnvSetupError
        expect(e.kind).toBe("patchelf-failed")
        // detail.binaryPath should equal the target (dst, not src)
        expect((e.detail as { binaryPath?: string }).binaryPath).toBe(dst)
      }
    })

    test("patchelf ENOENT → EnvSetupError(patchelf-not-available)", () => {
      const fakeSpawn: SpawnFn = () => {
        const err = Object.assign(new Error("spawn ENOENT"), {
          code: "ENOENT",
        })
        throw err
      }

      try {
        patchElf(
          {
            srcPath: env.binaryPath,
            interpreter: env.ldPath,
          },
          { spawn: fakeSpawn },
        )
        throw new Error("expected EnvSetupError")
      } catch (err) {
        expect(err).toBeInstanceOf(EnvSetupError)
        expect((err as EnvSetupError).kind).toBe("patchelf-not-available")
      }
    })

    test("replacements with multiple entries: each becomes --replace-needed <soname> <abs>", () => {
      const dst = join(env.libcDir, "prob")
      let capturedArgs: readonly string[] = []
      const fakeSpawn: SpawnFn = (cmd, args) => {
        capturedArgs = Array.from(args)
        return { exitCode: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }
      }

      patchElf(
        {
          srcPath: env.binaryPath,
          dstPath: dst,
          replacements: {
            "libc.so.6": "/a/libc.so.6",
            "libm.so.6": "/a/libm.so.6",
            "libz.so.1": "/a/libz.so.1",
          },
        },
        { spawn: fakeSpawn },
      )

      // 3 --replace-needed entries, each with [soname, absPath]
      const flagIndices = capturedArgs
        .map((a, i) => (a === "--replace-needed" ? i : -1))
        .filter((i) => i !== -1)
      expect(flagIndices.length).toBe(3)
      for (const i of flagIndices) {
        const soname = capturedArgs[i + 1]!
        const abs = capturedArgs[i + 2]!
        expect(["libc.so.6", "libm.so.6", "libz.so.1"]).toContain(soname)
        expect(abs.startsWith("/a/")).toBe(true)
      }
    })
  })
})
