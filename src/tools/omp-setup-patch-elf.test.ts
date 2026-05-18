/**
 * Tests for omp_setup_patch_elf (T07).
 *
 * Verifies tool-layer wiring + validation. Core patchelf logic is covered
 * by patchElf library tests in src/envsetup/patch-elf.test.ts — these
 * tests focus on input validation, error mapping, and that the tool
 * calls the library with the right shape.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, readFileSync } from "node:fs"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createOmpSetupPatchElfTool } from "./omp-setup-patch-elf"
import type { SpawnFn } from "../envsetup/patch-elf"

const TOOL_CTX = {
  sessionID: "s",
  messageID: "m",
  abort: new AbortController().signal,
  metadata: () => {},
} as never

const ORIGINAL = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0xab])

interface Harness {
  root: string
  src: string
}

async function setupHarness(): Promise<Harness> {
  const root = await mkdtemp(join(tmpdir(), "omp-patch-elf-test-"))
  const src = join(root, "input-binary")
  await writeFile(src, ORIGINAL)
  return { root, src }
}

async function teardown(h: Harness): Promise<void> {
  await rm(h.root, { recursive: true, force: true })
}

function noopPatchelfSpawn(): SpawnFn {
  return () => ({
    exitCode: 0,
    stdout: Buffer.alloc(0),
    stderr: Buffer.alloc(0),
  })
}

describe("omp_setup_patch_elf", () => {
  let h: Harness

  beforeEach(async () => {
    h = await setupHarness()
  })
  afterEach(async () => {
    await teardown(h)
  })

  /* ── validation ─────────────────────────────────────────────────────── */

  test("rejects non-absolute src_path", async () => {
    const t = createOmpSetupPatchElfTool({ spawn: noopPatchelfSpawn() })
    const raw = await t.execute(
      { src_path: "relative/binary" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("src_not_absolute")
  })

  test("source_missing when src_path does not exist", async () => {
    const t = createOmpSetupPatchElfTool({ spawn: noopPatchelfSpawn() })
    const raw = await t.execute(
      { src_path: join(h.root, "nope") },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("source_missing")
  })

  test("rejects non-absolute dst_path", async () => {
    const t = createOmpSetupPatchElfTool({ spawn: noopPatchelfSpawn() })
    const raw = await t.execute(
      {
        src_path: h.src,
        dst_path: "relative/dest",
        interpreter: "/abs/ld",
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("dst_not_absolute")
  })

  test("rejects non-absolute interpreter", async () => {
    const t = createOmpSetupPatchElfTool({ spawn: noopPatchelfSpawn() })
    const raw = await t.execute(
      {
        src_path: h.src,
        interpreter: "relative/ld",
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("interpreter_not_absolute")
  })

  test("rejects non-absolute replacement target", async () => {
    const t = createOmpSetupPatchElfTool({ spawn: noopPatchelfSpawn() })
    const raw = await t.execute(
      {
        src_path: h.src,
        replacements: { "libc.so.6": "relative/libc.so.6" },
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("replacement_not_absolute")
  })

  test("rejects when neither interpreter nor replacements supplied", async () => {
    const t = createOmpSetupPatchElfTool({ spawn: noopPatchelfSpawn() })
    const raw = await t.execute(
      {
        src_path: h.src,
        dst_path: join(h.root, "dst"),
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("nothing_to_patch")
  })

  test("empty replacements object is treated as none", async () => {
    const t = createOmpSetupPatchElfTool({ spawn: noopPatchelfSpawn() })
    const raw = await t.execute(
      {
        src_path: h.src,
        replacements: {},
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("nothing_to_patch")
  })

  /* ── binary case (copy + interp + replacements) ─────────────────────── */

  test("binary case: copy + interpreter + replacements happy path", async () => {
    const dst = join(h.root, "artifacts", "prob")
    let capturedArgs: string[] = []
    const spy: SpawnFn = (_cmd, args) => {
      capturedArgs = Array.from(args)
      return { exitCode: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }
    }
    const t = createOmpSetupPatchElfTool({ spawn: spy })

    const raw = await t.execute(
      {
        src_path: h.src,
        dst_path: dst,
        interpreter: "/abs/ld-linux-x86-64.so.2",
        replacements: {
          "libc.so.6": "/abs/libc.so.6",
          "libm.so.6": "/abs/libm.so.6",
        },
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)

    expect(out.ok).toBe(true)
    expect(out.patched_path).toBe(dst)
    expect(out.invoked_patchelf).toBe(true)
    // dst exists, src untouched
    expect(existsSync(dst)).toBe(true)
    expect(readFileSync(h.src)).toEqual(ORIGINAL)
    // patchelf args
    expect(capturedArgs).toContain("--set-interpreter")
    expect(capturedArgs).toContain("/abs/ld-linux-x86-64.so.2")
    expect(
      capturedArgs.filter((a) => a === "--replace-needed").length,
    ).toBe(2)
    expect(capturedArgs).not.toContain("--set-rpath")
  })

  /* ── library case (in-place + replacements only) ────────────────────── */

  test("library case: in-place + replacements only (no interpreter)", async () => {
    let capturedArgs: string[] = []
    const spy: SpawnFn = (_cmd, args) => {
      capturedArgs = Array.from(args)
      return { exitCode: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }
    }
    const t = createOmpSetupPatchElfTool({ spawn: spy })

    const raw = await t.execute(
      {
        src_path: h.src,
        replacements: {
          "libc.so.6": "/abs/libc.so.6",
        },
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)

    expect(out.ok).toBe(true)
    expect(out.patched_path).toBe(h.src)  // in-place
    expect(capturedArgs).not.toContain("--set-interpreter")
    expect(capturedArgs).toContain("--replace-needed")
    expect(capturedArgs).toContain("libc.so.6")
    expect(capturedArgs).toContain("/abs/libc.so.6")
  })

  /* ── error mapping ──────────────────────────────────────────────────── */

  test("patchelf ENOENT → patchelf-not-available typed error", async () => {
    const failingSpawn: SpawnFn = () => {
      const err = Object.assign(new Error("spawn patchelf ENOENT"), {
        code: "ENOENT",
      })
      throw err
    }
    const t = createOmpSetupPatchElfTool({ spawn: failingSpawn })

    const raw = await t.execute(
      { src_path: h.src, interpreter: "/abs/ld" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("patchelf-not-available")
  })

  test("patchelf non-zero exit → patchelf-failed typed error", async () => {
    const failingSpawn: SpawnFn = () => ({
      exitCode: 1,
      stdout: Buffer.alloc(0),
      stderr: Buffer.from("patchelf: cannot find a free slot\n", "utf-8"),
    })
    const t = createOmpSetupPatchElfTool({ spawn: failingSpawn })

    const raw = await t.execute(
      { src_path: h.src, interpreter: "/abs/ld" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("patchelf-failed")
    expect(out.detail?.exitCode).toBe(1)
  })
})
