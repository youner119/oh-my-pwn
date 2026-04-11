import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  ElfParseError,
  hasInterpSegment,
  parseElfMitigations,
} from "./elf-mitigations"
import {
  buildElfFixture,
  TEST_DF_1_NOW,
  TEST_DF_BIND_NOW,
  TEST_DT_BIND_NOW,
  TEST_DT_FLAGS,
  TEST_DT_FLAGS_1,
  TEST_PF_R,
  TEST_PF_W,
  TEST_PF_X,
  TEST_PT_DYNAMIC,
  TEST_PT_GNU_RELRO,
  TEST_PT_GNU_STACK,
  TEST_PT_INTERP,
  TEST_PT_LOAD,
} from "./elf-test-fixtures"

function makeTmp(label: string): string {
  const dir = join(
    tmpdir(),
    `omp-elf-test-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  )
  mkdirSync(dir, { recursive: true })
  return dir
}

function writeFixture(dir: string, name: string, bytes: Buffer): string {
  const path = join(dir, name)
  writeFileSync(path, bytes)
  return path
}

describe("parseElfMitigations", () => {
  let dir: string

  beforeEach(() => {
    dir = makeTmp("parser")
  })

  afterEach(() => {
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  describe("NX", () => {
    test("off when PT_GNU_STACK is absent (kernel default)", () => {
      const buf = buildElfFixture({
        type: "exec",
        programHeaders: [{ type: TEST_PT_LOAD, flags: TEST_PF_R | TEST_PF_X }],
      })
      const path = writeFixture(dir, "no-gnu-stack", buf)
      expect(parseElfMitigations(path).nx).toBe(false)
    })

    test("off when PT_GNU_STACK has PF_X set (executable stack)", () => {
      const buf = buildElfFixture({
        type: "exec",
        programHeaders: [
          { type: TEST_PT_GNU_STACK, flags: TEST_PF_R | TEST_PF_W | TEST_PF_X },
        ],
      })
      const path = writeFixture(dir, "exec-stack", buf)
      expect(parseElfMitigations(path).nx).toBe(false)
    })

    test("on when PT_GNU_STACK has PF_X clear", () => {
      const buf = buildElfFixture({
        type: "exec",
        programHeaders: [
          { type: TEST_PT_GNU_STACK, flags: TEST_PF_R | TEST_PF_W },
        ],
      })
      const path = writeFixture(dir, "nx-on", buf)
      expect(parseElfMitigations(path).nx).toBe(true)
    })
  })

  describe("PIE", () => {
    test("off for ET_EXEC binaries", () => {
      const buf = buildElfFixture({
        type: "exec",
        programHeaders: [{ type: TEST_PT_INTERP }],
      })
      const path = writeFixture(dir, "et-exec", buf)
      expect(parseElfMitigations(path).pie).toBe(false)
    })

    test("on for ET_DYN binaries with PT_INTERP", () => {
      const buf = buildElfFixture({
        type: "dyn",
        programHeaders: [{ type: TEST_PT_INTERP }],
      })
      const path = writeFixture(dir, "pie-on", buf)
      expect(parseElfMitigations(path).pie).toBe(true)
    })

    test("off for ET_DYN without PT_INTERP (i.e. a shared library)", () => {
      const buf = buildElfFixture({
        type: "dyn",
        programHeaders: [{ type: TEST_PT_LOAD, flags: TEST_PF_R | TEST_PF_X }],
      })
      const path = writeFixture(dir, "shared-lib", buf)
      expect(parseElfMitigations(path).pie).toBe(false)
    })
  })

  describe("Canary", () => {
    test("on when __stack_chk_fail is in .dynsym", () => {
      const buf = buildElfFixture({
        type: "exec",
        dynsymNames: ["printf", "__stack_chk_fail", "exit"],
      })
      const path = writeFixture(dir, "canary-dynsym", buf)
      expect(parseElfMitigations(path).canary).toBe(true)
    })

    test("on when __stack_chk_fail is in .symtab", () => {
      const buf = buildElfFixture({
        type: "exec",
        symtabNames: ["main", "__stack_chk_fail"],
      })
      const path = writeFixture(dir, "canary-symtab", buf)
      expect(parseElfMitigations(path).canary).toBe(true)
    })

    test("off when no symbol table is present", () => {
      const buf = buildElfFixture({ type: "exec" })
      const path = writeFixture(dir, "no-syms", buf)
      expect(parseElfMitigations(path).canary).toBe(false)
    })

    test("off when symbols are present but no __stack_chk_fail", () => {
      const buf = buildElfFixture({
        type: "exec",
        dynsymNames: ["printf", "exit", "puts"],
      })
      const path = writeFixture(dir, "no-canary-sym", buf)
      expect(parseElfMitigations(path).canary).toBe(false)
    })
  })

  describe("RELRO", () => {
    test("none when neither PT_GNU_RELRO nor BIND_NOW is present", () => {
      const buf = buildElfFixture({
        type: "exec",
        programHeaders: [{ type: TEST_PT_LOAD }],
      })
      const path = writeFixture(dir, "no-relro", buf)
      expect(parseElfMitigations(path).relro).toBe("none")
    })

    test("partial when PT_GNU_RELRO exists but no BIND_NOW", () => {
      const buf = buildElfFixture({
        type: "exec",
        programHeaders: [
          { type: TEST_PT_GNU_RELRO },
          { type: TEST_PT_DYNAMIC, pointsAtDynamic: true },
        ],
        dynamic: [{ tag: 1, val: 0 }], // DT_NEEDED, irrelevant payload
      })
      const path = writeFixture(dir, "partial-relro", buf)
      expect(parseElfMitigations(path).relro).toBe("partial")
    })

    test("full when PT_GNU_RELRO + DT_BIND_NOW", () => {
      const buf = buildElfFixture({
        type: "exec",
        programHeaders: [
          { type: TEST_PT_GNU_RELRO },
          { type: TEST_PT_DYNAMIC, pointsAtDynamic: true },
        ],
        dynamic: [{ tag: TEST_DT_BIND_NOW, val: 0 }],
      })
      const path = writeFixture(dir, "full-relro-bindnow", buf)
      expect(parseElfMitigations(path).relro).toBe("full")
    })

    test("full when PT_GNU_RELRO + DT_FLAGS contains DF_BIND_NOW", () => {
      const buf = buildElfFixture({
        type: "exec",
        programHeaders: [
          { type: TEST_PT_GNU_RELRO },
          { type: TEST_PT_DYNAMIC, pointsAtDynamic: true },
        ],
        dynamic: [{ tag: TEST_DT_FLAGS, val: TEST_DF_BIND_NOW }],
      })
      const path = writeFixture(dir, "full-relro-dtflags", buf)
      expect(parseElfMitigations(path).relro).toBe("full")
    })

    test("full when PT_GNU_RELRO + DT_FLAGS_1 contains DF_1_NOW", () => {
      const buf = buildElfFixture({
        type: "exec",
        programHeaders: [
          { type: TEST_PT_GNU_RELRO },
          { type: TEST_PT_DYNAMIC, pointsAtDynamic: true },
        ],
        dynamic: [{ tag: TEST_DT_FLAGS_1, val: TEST_DF_1_NOW }],
      })
      const path = writeFixture(dir, "full-relro-dtflags1", buf)
      expect(parseElfMitigations(path).relro).toBe("full")
    })
  })

  describe("raw summary", () => {
    test("contains all four mitigation states", () => {
      const buf = buildElfFixture({
        type: "dyn",
        programHeaders: [
          { type: TEST_PT_INTERP },
          { type: TEST_PT_GNU_STACK, flags: TEST_PF_R | TEST_PF_W },
          { type: TEST_PT_GNU_RELRO },
          { type: TEST_PT_DYNAMIC, pointsAtDynamic: true },
        ],
        dynamic: [{ tag: TEST_DT_BIND_NOW, val: 0 }],
        dynsymNames: ["__stack_chk_fail"],
      })
      const path = writeFixture(dir, "all-on", buf)
      const result = parseElfMitigations(path)
      expect(result).toEqual({
        nx: true,
        pie: true,
        canary: true,
        relro: "full",
        raw: "NX=on PIE=on Canary=on RELRO=full",
      })
    })
  })

  describe("ELF32 support", () => {
    test("parses a minimal 32-bit ELF", () => {
      const buf = buildElfFixture({
        class: 32,
        type: "exec",
        programHeaders: [
          { type: TEST_PT_GNU_STACK, flags: TEST_PF_R | TEST_PF_W },
        ],
      })
      const path = writeFixture(dir, "elf32", buf)
      expect(parseElfMitigations(path).nx).toBe(true)
    })
  })

  describe("error cases", () => {
    test("throws ElfParseError on missing magic", () => {
      const path = writeFixture(dir, "not-elf", Buffer.from("MZ\x90\x00"))
      try {
        parseElfMitigations(path)
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(ElfParseError)
        expect((err as ElfParseError).reason).toContain("magic mismatch")
      }
    })

    test("throws ElfParseError on truncated header", () => {
      const path = writeFixture(
        dir,
        "tiny",
        Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
      )
      try {
        parseElfMitigations(path)
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(ElfParseError)
      }
    })

    test("throws ElfParseError on read failure", () => {
      try {
        parseElfMitigations(join(dir, "does-not-exist"))
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(ElfParseError)
      }
    })
  })
})

describe("hasInterpSegment", () => {
  let dir: string

  beforeEach(() => {
    dir = makeTmp("interp")
  })

  afterEach(() => {
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test("true when PT_INTERP is present (dynamically linked)", () => {
    const buf = buildElfFixture({
      type: "exec",
      programHeaders: [{ type: TEST_PT_INTERP }],
    })
    const path = writeFixture(dir, "dynamic", buf)
    expect(hasInterpSegment(path)).toBe(true)
  })

  test("false when PT_INTERP is absent (static)", () => {
    const buf = buildElfFixture({
      type: "exec",
      programHeaders: [{ type: TEST_PT_LOAD }],
    })
    const path = writeFixture(dir, "static", buf)
    expect(hasInterpSegment(path)).toBe(false)
  })

  test("false on a non-existent file (does not throw)", () => {
    expect(hasInterpSegment(join(dir, "ghost"))).toBe(false)
  })

  test("false on a non-ELF file (does not throw)", () => {
    const path = writeFixture(dir, "garbage", Buffer.from("not elf"))
    expect(hasInterpSegment(path)).toBe(false)
  })
})
