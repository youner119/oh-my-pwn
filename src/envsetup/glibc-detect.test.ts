import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  detectGlibcVersion,
  detectGlibcVersionFromBytes,
} from "./glibc-detect"

function makeTmp(label: string): string {
  const dir = join(
    tmpdir(),
    `omp-glibc-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  )
  mkdirSync(dir, { recursive: true })
  return dir
}

describe("detectGlibcVersionFromBytes", () => {
  test("parses upstream banner format (glibc 2.31)", () => {
    const banner =
      "GNU C Library (GNU libc) stable release version 2.31.\n" +
      "Copyright (C) 2020 Free Software Foundation, Inc."
    const padded = Buffer.concat([
      Buffer.alloc(4096),
      Buffer.from(banner, "utf-8"),
      Buffer.alloc(4096),
    ])
    expect(detectGlibcVersionFromBytes(padded)).toBe("2.31")
  })

  test("parses Ubuntu-tagged banner (glibc 2.35)", () => {
    const banner =
      "GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.4) stable release version 2.35.\n"
    const buf = Buffer.from(banner, "utf-8")
    expect(detectGlibcVersionFromBytes(buf)).toBe("2.35")
  })

  test("parses Debian-tagged banner (glibc 2.36)", () => {
    const banner =
      "GNU C Library (Debian GLIBC 2.36-9+deb12u4) stable release version 2.36."
    const buf = Buffer.from(banner, "utf-8")
    expect(detectGlibcVersionFromBytes(buf)).toBe("2.36")
  })

  test("captures optional patch level (2.31.1)", () => {
    const banner = "GNU C Library stable release version 2.31.1.\n"
    expect(detectGlibcVersionFromBytes(Buffer.from(banner, "utf-8"))).toBe(
      "2.31.1",
    )
  })

  test("returns null on a musl libc (no GNU banner)", () => {
    // musl uses a different banner: "musl libc (x86_64)\nVersion 1.2.4\n..."
    const musl = "musl libc (x86_64)\nVersion 1.2.4\n"
    expect(detectGlibcVersionFromBytes(Buffer.from(musl, "utf-8"))).toBeNull()
  })

  test("returns null on an empty buffer", () => {
    expect(detectGlibcVersionFromBytes(Buffer.alloc(0))).toBeNull()
  })

  test("returns null on a buffer with no banner anywhere", () => {
    const garbage = Buffer.alloc(8192).fill(0x42)
    expect(detectGlibcVersionFromBytes(garbage)).toBeNull()
  })
})

describe("detectGlibcVersion (file I/O)", () => {
  let dir: string

  beforeEach(() => {
    dir = makeTmp("file")
  })

  afterEach(() => {
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test("reads a real file and detects 2.35", () => {
    const path = join(dir, "libc.so.6")
    writeFileSync(
      path,
      "GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3) stable release version 2.35.\n",
    )
    expect(detectGlibcVersion(path)).toBe("2.35")
  })

  test("returns null on a non-existent file (does not throw)", () => {
    expect(detectGlibcVersion(join(dir, "missing"))).toBeNull()
  })
})
