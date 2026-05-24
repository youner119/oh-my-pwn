import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { chmodSync, existsSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  detectBinary,
  isElf,
  isExecutable,
  looksLikeSharedObject,
} from "./binary-detect"

const ELF_HEADER = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00])

function makeChallengeDir(label: string): string {
  const dir = join(
    tmpdir(),
    `omp-binary-detect-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  )
  mkdirSync(dir, { recursive: true })
  return dir
}

function writeElf(dir: string, name: string, mode = 0o755): string {
  const path = join(dir, name)
  writeFileSync(path, ELF_HEADER)
  chmodSync(path, mode)
  return path
}

function writePlain(dir: string, name: string, content: string, mode = 0o644): string {
  const path = join(dir, name)
  writeFileSync(path, content)
  chmodSync(path, mode)
  return path
}

describe("binary-detect", () => {
  let dir: string

  beforeEach(() => {
    dir = makeChallengeDir("d")
  })

  afterEach(() => {
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  describe("isElf", () => {
    test("true for files starting with the ELF magic", () => {
      const p = writeElf(dir, "chall")
      expect(isElf(p)).toBe(true)
    })

    test("false for plain text files", () => {
      const p = writePlain(dir, "notes.txt", "hello world\n")
      expect(isElf(p)).toBe(false)
    })

    test("false for files shorter than 4 bytes", () => {
      const p = writePlain(dir, "tiny", "ab")
      expect(isElf(p)).toBe(false)
    })

    test("false for nonexistent paths", () => {
      expect(isElf(join(dir, "does-not-exist"))).toBe(false)
    })
  })

  describe("isExecutable", () => {
    test("true when any execute bit is set", () => {
      const p = writeElf(dir, "chall", 0o755)
      expect(isExecutable(p)).toBe(true)
    })

    test("false when no execute bit is set", () => {
      const p = writeElf(dir, "chall", 0o644)
      expect(isExecutable(p)).toBe(false)
    })

    test("false for nonexistent paths", () => {
      expect(isExecutable(join(dir, "missing"))).toBe(false)
    })
  })

  describe("looksLikeSharedObject", () => {
    test("matches common libc/ld/.so patterns", () => {
      expect(looksLikeSharedObject("libc.so.6")).toBe(true)
      expect(looksLikeSharedObject("libc-2.31.so")).toBe(true)
      expect(looksLikeSharedObject("ld-linux-x86-64.so.2")).toBe(true)
      expect(looksLikeSharedObject("ld-2.31.so")).toBe(true)
      expect(looksLikeSharedObject("libpthread-2.31.so")).toBe(true)
      expect(looksLikeSharedObject("libstdc++.so.6")).toBe(true)
      expect(looksLikeSharedObject("foo.so")).toBe(true)
      expect(looksLikeSharedObject("foo.so.1.2")).toBe(true)
    })

    test("does not match plausible challenge binary names", () => {
      expect(looksLikeSharedObject("chall")).toBe(false)
      expect(looksLikeSharedObject("vuln")).toBe(false)
      expect(looksLikeSharedObject("pwn")).toBe(false)
      expect(looksLikeSharedObject("notes")).toBe(false)
      expect(looksLikeSharedObject("app")).toBe(false)
    })
  })

  describe("detectBinary", () => {
    test("returns {kind:'ok'} with the lone executable ELF when only one candidate exists", () => {
      const expected = writeElf(dir, "chall")
      writePlain(dir, "Dockerfile", "FROM ubuntu\n")
      writePlain(dir, "README.md", "# challenge\n")
      expect(detectBinary(dir)).toEqual({ kind: "ok", path: expected })
    })

    test("excludes libc/ld/.so siblings even when they are executable ELFs", () => {
      const expected = writeElf(dir, "chall")
      writeElf(dir, "libc.so.6")
      writeElf(dir, "ld-linux-x86-64.so.2")
      expect(detectBinary(dir)).toEqual({ kind: "ok", path: expected })
    })

    test("excludes ELF files without the executable bit", () => {
      const expected = writeElf(dir, "chall")
      writeElf(dir, "old-binary", 0o644)
      expect(detectBinary(dir)).toEqual({ kind: "ok", path: expected })
    })

    test("excludes plain non-ELF files even when executable", () => {
      const expected = writeElf(dir, "chall")
      writePlain(dir, "run.sh", "#!/bin/sh\necho hi\n", 0o755)
      expect(detectBinary(dir)).toEqual({ kind: "ok", path: expected })
    })

    test("returns {kind:'none'} when no candidate is found", () => {
      writePlain(dir, "Dockerfile", "FROM ubuntu\n")
      writePlain(dir, "notes.txt", "nothing here\n")
      expect(detectBinary(dir)).toEqual({ kind: "none" })
    })

    test("returns {kind:'multiple'} with every candidate when more than one exists", () => {
      const a = writeElf(dir, "chall_a")
      const b = writeElf(dir, "chall_b")
      const result = detectBinary(dir)
      expect(result.kind).toBe("multiple")
      if (result.kind === "multiple") {
        expect(result.candidates.sort()).toEqual([a, b].sort())
      }
    })

    test("follows a symlink-to-binary stored outside the challenge dir", () => {
      // Real binary lives in a sibling tmp folder; only the symlink sits in dir.
      const sidecar = makeChallengeDir("sidecar")
      try {
        const realPath = writeElf(sidecar, "real.elf")
        const linkPath = join(dir, "chall")
        symlinkSync(realPath, linkPath)

        expect(detectBinary(dir)).toEqual({ kind: "ok", path: linkPath })
      } finally {
        rmSync(sidecar, { recursive: true, force: true })
      }
    })

    test("ignores subdirectories during detection", () => {
      const expected = writeElf(dir, "chall")
      mkdirSync(join(dir, "src"), { recursive: true })
      writeElf(join(dir, "src"), "helper")
      expect(detectBinary(dir)).toEqual({ kind: "ok", path: expected })
    })
  })
})
