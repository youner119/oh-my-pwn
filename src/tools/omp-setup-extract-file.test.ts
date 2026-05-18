/**
 * Tests for omp_setup_extract_file (T06).
 *
 * Covers:
 *   - image source: create + cp + rm sequence with FakeDockerRunner
 *     (responder simulates file creation at dest)
 *   - host source: copyFile vs preserve-symlink behaviour
 *   - dereference_symlinks flag (true default / explicit false)
 *   - validation: invalid_source / dest_not_absolute / src_not_absolute /
 *     image_tag_required
 *   - failure modes: source_missing / docker-not-available /
 *     docker-create-failed / docker-cp-failed / dest_missing_after_copy
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, writeFileSync } from "node:fs"
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { createHash } from "node:crypto"
import { join } from "node:path"
import { createOmpSetupExtractFileTool } from "./omp-setup-extract-file"
import {
  FakeDockerRunner,
  dockerEnoentError,
} from "../envsetup/fake-docker-runner"

const TOOL_CTX = {
  sessionID: "s",
  messageID: "m",
  abort: new AbortController().signal,
  metadata: () => {},
} as never

interface Harness {
  root: string
}

async function setupHarness(): Promise<Harness> {
  const root = await mkdtemp(join(tmpdir(), "omp-extract-test-"))
  return { root }
}

async function teardown(h: Harness): Promise<void> {
  await rm(h.root, { recursive: true, force: true })
}

function sha256Hex(content: Buffer | string): string {
  return createHash("sha256")
    .update(typeof content === "string" ? Buffer.from(content) : content)
    .digest("hex")
}

/** FakeDockerRunner factory: docker create/cp/rm with file-creation side effect on cp. */
function fakeImageRunner(opts: {
  cpExit?: number
  cpStderr?: string
  cpFileContent?: string
  containerId?: string
  createExit?: number
  throwOn?: "create" | "cp"
} = {}): FakeDockerRunner {
  const containerId = opts.containerId ?? "fake-cid-abc123"
  return new FakeDockerRunner((call) => {
    const verb = call.args[0]
    if (verb === "create") {
      if (opts.throwOn === "create") {
        return { exitCode: 0, throwError: dockerEnoentError() }
      }
      return {
        exitCode: opts.createExit ?? 0,
        stdout: opts.createExit !== undefined && opts.createExit !== 0
          ? ""
          : `${containerId}\n`,
      }
    }
    if (verb === "cp") {
      if (opts.throwOn === "cp") {
        return { exitCode: 0, throwError: dockerEnoentError() }
      }
      const exit = opts.cpExit ?? 0
      // Simulate file creation at destPath on success.
      if (exit === 0 && opts.cpFileContent !== undefined) {
        const dest = call.args[call.args.length - 1]
        writeFileSync(dest, opts.cpFileContent)
      }
      return { exitCode: exit, stderr: opts.cpStderr }
    }
    if (verb === "rm") {
      return { exitCode: 0 }
    }
    return { exitCode: 0 }
  })
}

describe("omp_setup_extract_file", () => {
  let h: Harness

  beforeEach(async () => {
    h = await setupHarness()
  })
  afterEach(async () => {
    await teardown(h)
  })

  /* ── validation ─────────────────────────────────────────────────────── */

  test("rejects invalid source kind", async () => {
    const t = createOmpSetupExtractFileTool({ runner: fakeImageRunner() })
    const raw = await t.execute(
      {
        source: "ftp",
        src_path: "/x",
        dest_path: "/y",
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("invalid_source")
  })

  test("rejects non-absolute dest_path", async () => {
    const t = createOmpSetupExtractFileTool({ runner: fakeImageRunner() })
    const raw = await t.execute(
      {
        source: "host",
        src_path: "/abs/src",
        dest_path: "relative",
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("dest_not_absolute")
  })

  test("rejects non-absolute src_path", async () => {
    const t = createOmpSetupExtractFileTool({ runner: fakeImageRunner() })
    const raw = await t.execute(
      {
        source: "host",
        src_path: "relative/src",
        dest_path: "/abs/dest",
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("src_not_absolute")
  })

  test("rejects source=image without image_tag", async () => {
    const t = createOmpSetupExtractFileTool({ runner: fakeImageRunner() })
    const raw = await t.execute(
      {
        source: "image",
        src_path: "/lib/x86_64-linux-gnu/libc.so.6",
        dest_path: join(h.root, "libc.so.6"),
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("image_tag_required")
  })

  /* ── host source ────────────────────────────────────────────────────── */

  test("host source: copyFile with dereference=true (default)", async () => {
    const src = join(h.root, "libc.so.6")
    const content = "ELFLIBC_CONTENT"
    await writeFile(src, content)
    const dest = join(h.root, "dest", "libc.so.6")  // parent autocreated

    const t = createOmpSetupExtractFileTool({ runner: fakeImageRunner() })
    const raw = await t.execute(
      {
        source: "host",
        src_path: src,
        dest_path: dest,
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(true)
    expect(out.dest_path).toBe(dest)
    expect(out.sha256).toBe(sha256Hex(content))
    expect(out.size).toBe(content.length)
    expect(existsSync(dest)).toBe(true)
  })

  test("host source: preserve symlink with dereference=false", async () => {
    const target = join(h.root, "libc.so.6.real")
    await writeFile(target, "TARGET_CONTENT")
    const src = join(h.root, "libc.so.6.symlink")
    await symlink(target, src)
    const dest = join(h.root, "stage", "libc.so.6.symlink")

    const t = createOmpSetupExtractFileTool({ runner: fakeImageRunner() })
    const raw = await t.execute(
      {
        source: "host",
        src_path: src,
        dest_path: dest,
        dereference_symlinks: false,
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(true)
    expect(existsSync(dest)).toBe(true)
    // statSync (used internally) dereferences, so size reflects target.
    expect(out.size).toBe("TARGET_CONTENT".length)
  })

  test("host source: dereference=true on symlink follows to realfile", async () => {
    const target = join(h.root, "libz.so.1.3")
    const content = "REALCONTENT"
    await writeFile(target, content)
    const src = join(h.root, "libz.so.1")
    await symlink(target, src)
    const dest = join(h.root, "stage", "libz.so.1")

    const t = createOmpSetupExtractFileTool({ runner: fakeImageRunner() })
    const raw = await t.execute(
      {
        source: "host",
        src_path: src,
        dest_path: dest,
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(true)
    // After dereferencing copy, dest contains the realfile bytes.
    expect(await readFile(dest, "utf-8")).toBe(content)
    expect(out.sha256).toBe(sha256Hex(content))
  })

  test("host source: source_missing when file absent", async () => {
    const t = createOmpSetupExtractFileTool({ runner: fakeImageRunner() })
    const raw = await t.execute(
      {
        source: "host",
        src_path: join(h.root, "nonexistent"),
        dest_path: join(h.root, "dest"),
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("source_missing")
  })

  /* ── image source ───────────────────────────────────────────────────── */

  test("image source: create + cp + rm sequence with file creation", async () => {
    const dest = join(h.root, "artifacts", "libc.so.6")
    const fakeContent = "DOCKER_LIBC"
    const runner = fakeImageRunner({ cpFileContent: fakeContent })
    const t = createOmpSetupExtractFileTool({ runner })

    const raw = await t.execute(
      {
        source: "image",
        image_tag: "omp-abc123",
        src_path: "/lib/x86_64-linux-gnu/libc.so.6",
        dest_path: dest,
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)

    expect(out.ok).toBe(true)
    expect(out.dest_path).toBe(dest)
    expect(out.sha256).toBe(sha256Hex(fakeContent))
    expect(out.size).toBe(fakeContent.length)

    // Verify the sequence: create → cp -L → rm -f
    const verbs = runner.calls.map((c) => c.args[0])
    expect(verbs).toEqual(["create", "cp", "rm"])
    const cpCall = runner.calls[1]
    expect(cpCall?.args).toContain("-L")  // dereference=true default
    expect(cpCall?.args).toContain("fake-cid-abc123:/lib/x86_64-linux-gnu/libc.so.6")
  })

  test("image source: dereference=false omits -L flag", async () => {
    const dest = join(h.root, "stage", "libbz2.so.1.0")
    const runner = fakeImageRunner({ cpFileContent: "x" })
    const t = createOmpSetupExtractFileTool({ runner })

    await t.execute(
      {
        source: "image",
        image_tag: "omp-abc123",
        src_path: "/usr/lib/x86_64-linux-gnu/libbz2.so.1.0",
        dest_path: dest,
        dereference_symlinks: false,
      },
      TOOL_CTX,
    )

    const cpCall = runner.calls[1]
    expect(cpCall?.args).not.toContain("-L")
  })

  test("image source: cleanup runs (rm -f containerId) even on cp failure", async () => {
    const runner = fakeImageRunner({ cpExit: 1, cpStderr: "lstat: No such file" })
    const t = createOmpSetupExtractFileTool({ runner })

    const raw = await t.execute(
      {
        source: "image",
        image_tag: "omp-abc123",
        src_path: "/lib/nope",
        dest_path: join(h.root, "x"),
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("source_missing")  // pattern-matched from stderr

    const verbs = runner.calls.map((c) => c.args[0])
    expect(verbs).toEqual(["create", "cp", "rm"])
  })

  test("image source: docker create empty stdout → docker-create-failed", async () => {
    const runner = new FakeDockerRunner((call) => {
      if (call.args[0] === "create") {
        return { exitCode: 0, stdout: "" }  // empty container id
      }
      return { exitCode: 0 }
    })
    const t = createOmpSetupExtractFileTool({ runner })

    const raw = await t.execute(
      {
        source: "image",
        image_tag: "omp-abc123",
        src_path: "/lib/libc.so.6",
        dest_path: join(h.root, "out"),
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("docker-create-failed")
  })

  test("image source: docker not available (ENOENT) → docker-not-available", async () => {
    const runner = fakeImageRunner({ throwOn: "create" })
    const t = createOmpSetupExtractFileTool({ runner })

    const raw = await t.execute(
      {
        source: "image",
        image_tag: "omp-abc123",
        src_path: "/lib/libc.so.6",
        dest_path: join(h.root, "out"),
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("docker-not-available")
  })

  test("image source: generic cp failure → docker-cp-failed", async () => {
    // stderr that does NOT match the source_missing pattern.
    const runner = fakeImageRunner({ cpExit: 137, cpStderr: "killed: OOM" })
    const t = createOmpSetupExtractFileTool({ runner })

    const raw = await t.execute(
      {
        source: "image",
        image_tag: "omp-abc123",
        src_path: "/lib/libc.so.6",
        dest_path: join(h.root, "out"),
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("docker-cp-failed")
    expect(out.detail?.exit_code).toBe(137)
  })

  test("image source: cp success but dest missing → dest_missing_after_copy", async () => {
    // cpExit=0 but no cpFileContent supplied, so the responder doesn't create a file.
    const runner = fakeImageRunner({})
    const t = createOmpSetupExtractFileTool({ runner })

    const raw = await t.execute(
      {
        source: "image",
        image_tag: "omp-abc123",
        src_path: "/lib/libc.so.6",
        dest_path: join(h.root, "out"),
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("dest_missing_after_copy")
  })
})
