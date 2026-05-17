import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import { mkdtemp, mkdir, rm, writeFile, stat, utimes } from "node:fs/promises"
import { existsSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createOmpStageChallengeTool } from "./stage-challenge"

interface ToolHarness {
  challengeDir: string
  workspaceDir: string
  root: string
}

async function setupHarness(): Promise<ToolHarness> {
  const root = await mkdtemp(join(tmpdir(), "omp-stage-test-"))
  const challengeDir = join(root, "challenge", "afterimage")
  const workspaceDir = join(root, "workspace")
  await mkdir(challengeDir, { recursive: true })
  await mkdir(workspaceDir, { recursive: true })
  return { challengeDir, workspaceDir, root }
}

async function teardown(h: ToolHarness): Promise<void> {
  await rm(h.root, { recursive: true, force: true })
}

const TOOL_CTX = {
  sessionID: "s",
  messageID: "m",
  abort: new AbortController().signal,
  metadata: () => {},
} as never

function makeTool(h: ToolHarness) {
  return createOmpStageChallengeTool({ workspacePath: h.workspaceDir })
}

describe("omp_stage_challenge", () => {
  let h: ToolHarness

  beforeEach(async () => {
    h = await setupHarness()
  })
  afterEach(async () => {
    await teardown(h)
  })

  test("copies files on first run, sets container paths under /workspace/<id>", async () => {
    await writeFile(join(h.challengeDir, "chal"), "ELFBINARY")
    await writeFile(join(h.challengeDir, "libc.so.6"), "LIBCBLOB")

    const t = makeTool(h)
    const raw = await t.execute(
      {
        challenge_dir: h.challengeDir,
        files: ["chal", "libc.so.6"],
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)

    expect(out.ok).toBe(true)
    expect(out.challenge_id).toBe("afterimage")
    expect(out.container_dir).toBe("/workspace/afterimage")
    expect(out.staged).toHaveLength(2)
    expect(out.staged[0].action).toBe("copied")
    expect(out.staged[0].container_path).toBe("/workspace/afterimage/chal")
    expect(out.staged[1].container_path).toBe("/workspace/afterimage/libc.so.6")

    expect(existsSync(join(h.workspaceDir, "afterimage", "chal"))).toBe(true)
    expect(existsSync(join(h.workspaceDir, "afterimage", "libc.so.6"))).toBe(true)
  })

  test("idempotent: second run on unchanged files reports skipped", async () => {
    await writeFile(join(h.challengeDir, "chal"), "ELFBINARY")
    const t = makeTool(h)

    const first = JSON.parse(
      (await t.execute(
        { challenge_dir: h.challengeDir, files: ["chal"] },
        TOOL_CTX,
      )) as string,
    )
    expect(first.staged[0].action).toBe("copied")

    const second = JSON.parse(
      (await t.execute(
        { challenge_dir: h.challengeDir, files: ["chal"] },
        TOOL_CTX,
      )) as string,
    )
    expect(second.staged[0].action).toBe("skipped")
  })

  test("modified source triggers updated action", async () => {
    const src = join(h.challengeDir, "chal")
    await writeFile(src, "ORIGINAL")
    const t = makeTool(h)

    await t.execute(
      { challenge_dir: h.challengeDir, files: ["chal"] },
      TOOL_CTX,
    )

    // Replace contents AND bump mtime to ensure detection
    await writeFile(src, "MODIFIED_LONGER_BYTES")
    const future = new Date(Date.now() + 5_000)
    await utimes(src, future, future)

    const second = JSON.parse(
      (await t.execute(
        { challenge_dir: h.challengeDir, files: ["chal"] },
        TOOL_CTX,
      )) as string,
    )
    expect(second.staged[0].action).toBe("updated")

    const destStat = await stat(join(h.workspaceDir, "afterimage", "chal"))
    expect(destStat.size).toBe("MODIFIED_LONGER_BYTES".length)
  })

  test("missing source file is reported per-file, others still stage", async () => {
    await writeFile(join(h.challengeDir, "chal"), "OK")
    const t = makeTool(h)

    const raw = await t.execute(
      {
        challenge_dir: h.challengeDir,
        files: ["chal", "nonexistent.so"],
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)

    expect(out.ok).toBe(true)
    expect(out.staged).toHaveLength(2)
    expect(out.staged[0].action).toBe("copied")
    expect(out.staged[1].action).toBe("missing")
    expect(out.staged[1].error).toContain("does not exist")
  })

  test("rejects relative challenge_dir", async () => {
    const t = makeTool(h)
    const raw = await t.execute(
      { challenge_dir: "relative/path", files: [] },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("challenge_dir_not_absolute")
  })

  test("rejects nonexistent challenge_dir", async () => {
    const t = makeTool(h)
    const raw = await t.execute(
      { challenge_dir: join(h.root, "ghost"), files: [] },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("challenge_dir_missing")
  })

  test("challenge_id override changes target subdirectory", async () => {
    await writeFile(join(h.challengeDir, "chal"), "OK")
    const t = makeTool(h)

    const raw = await t.execute(
      {
        challenge_dir: h.challengeDir,
        files: ["chal"],
        challenge_id: "custom-name",
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.challenge_id).toBe("custom-name")
    expect(out.container_dir).toBe("/workspace/custom-name")
    expect(existsSync(join(h.workspaceDir, "custom-name", "chal"))).toBe(true)
  })

  test(".orig backup in .omp/artifacts/ is preferred over live file", async () => {
    const liveBin = join(h.challengeDir, "main")
    const origDir = join(h.challengeDir, ".omp", "artifacts")
    await mkdir(origDir, { recursive: true })
    await writeFile(liveBin, "PATCHED_BYTES")
    await writeFile(join(origDir, "main.orig"), "ORIGINAL_BYTES")

    const t = makeTool(h)
    const out = JSON.parse(
      (await t.execute(
        { challenge_dir: h.challengeDir, files: ["main"] },
        TOOL_CTX,
      )) as string,
    )

    expect(out.staged[0].source_kind).toBe("orig_backup")
    expect(out.staged[0].host_path).toContain(".omp/artifacts/main.orig")

    const stagedBytes = await Bun.file(
      join(h.workspaceDir, "afterimage", "main"),
    ).text()
    expect(stagedBytes).toBe("ORIGINAL_BYTES")
  })

  test("falls back to live file when no .orig backup exists", async () => {
    await writeFile(join(h.challengeDir, "main"), "LIVE_BYTES")
    const t = makeTool(h)
    const out = JSON.parse(
      (await t.execute(
        { challenge_dir: h.challengeDir, files: ["main"] },
        TOOL_CTX,
      )) as string,
    )
    expect(out.staged[0].source_kind).toBe("live")
  })

  test("patchelf is skipped when binary_name/libc_name/ld_name not all provided", async () => {
    await writeFile(join(h.challengeDir, "main"), "ELF")
    const t = makeTool(h)
    const out = JSON.parse(
      (await t.execute(
        {
          challenge_dir: h.challengeDir,
          files: ["main"],
          binary_name: "main",
          // libc_name + ld_name omitted
        },
        TOOL_CTX,
      )) as string,
    )
    expect(out.patchelf.applied).toBe(false)
    expect(out.patchelf.reason).toContain("skipped-args")
  })

  test("patchelf rewrites staged binary's interpreter + rpath to container paths", async () => {
    await writeFile(join(h.challengeDir, "main"), "ORIGINAL_ELF")
    await writeFile(join(h.challengeDir, "libc.so.6"), "LIBC")
    await writeFile(join(h.challengeDir, "ld-linux-x86-64.so.2"), "LD")

    const calls: Array<{ cmd: string; args: readonly string[] }> = []
    const fakeSpawn = (cmd: string, args: readonly string[]) => {
      calls.push({ cmd, args })
      return { exitCode: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }
    }
    const tool2 = createOmpStageChallengeTool({
      workspacePath: h.workspaceDir,
      patchelfSpawn: fakeSpawn,
    })

    const out = JSON.parse(
      (await tool2.execute(
        {
          challenge_dir: h.challengeDir,
          files: ["main", "libc.so.6", "ld-linux-x86-64.so.2"],
          binary_name: "main",
          libc_name: "libc.so.6",
          ld_name: "ld-linux-x86-64.so.2",
        },
        TOOL_CTX,
      )) as string,
    )

    expect(out.patchelf.applied).toBe(true)
    expect(out.patchelf.interpreter_set).toBe(
      "/workspace/afterimage/ld-linux-x86-64.so.2",
    )
    expect(out.patchelf.rpath_set).toBe("/workspace/afterimage")
    expect(out.patchelf.binary_host_path).toBe(
      join(h.workspaceDir, "afterimage", "main"),
    )
    expect(out.patchelf.backup_host_path).toContain(".host-orig")

    // patchelf was invoked exactly once with the expected args
    expect(calls).toHaveLength(1)
    expect(calls[0].cmd).toBe("patchelf")
    expect(calls[0].args).toEqual([
      "--set-interpreter",
      "/workspace/afterimage/ld-linux-x86-64.so.2",
      "--set-rpath",
      "/workspace/afterimage",
      join(h.workspaceDir, "afterimage", "main"),
    ])

    // backup directory was created and contains the pre-patch copy
    expect(
      existsSync(join(h.workspaceDir, "afterimage", ".host-orig", "main")),
    ).toBe(true)
  })

  test("patchelf reports source-missing when binary not staged", async () => {
    await writeFile(join(h.challengeDir, "libc.so.6"), "LIBC")
    await writeFile(join(h.challengeDir, "ld-linux-x86-64.so.2"), "LD")
    // No main file at all

    const tool2 = createOmpStageChallengeTool({
      workspacePath: h.workspaceDir,
      patchelfSpawn: () => ({
        exitCode: 0,
        stdout: Buffer.alloc(0),
        stderr: Buffer.alloc(0),
      }),
    })

    const out = JSON.parse(
      (await tool2.execute(
        {
          challenge_dir: h.challengeDir,
          files: ["main", "libc.so.6", "ld-linux-x86-64.so.2"],
          binary_name: "main",
          libc_name: "libc.so.6",
          ld_name: "ld-linux-x86-64.so.2",
        },
        TOOL_CTX,
      )) as string,
    )

    expect(out.patchelf.applied).toBe(false)
    expect(out.patchelf.reason).toContain("source-missing")
    expect(out.patchelf.reason).toContain("binary(main)")
  })

  test("flattens nested source paths to basename in workspace", async () => {
    // Source: deploy/chal — but destination is just <workspace>/<id>/chal
    await mkdir(join(h.challengeDir, "deploy"), { recursive: true })
    await writeFile(join(h.challengeDir, "deploy", "chal"), "NESTED")
    const t = makeTool(h)

    const raw = await t.execute(
      { challenge_dir: h.challengeDir, files: ["deploy/chal"] },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.staged[0].name).toBe("chal")
    expect(out.staged[0].container_path).toBe("/workspace/afterimage/chal")
    expect(existsSync(join(h.workspaceDir, "afterimage", "chal"))).toBe(true)
  })
})
