/**
 * Tests for omp_setup_verify_runtime (T08).
 *
 * Covers:
 *   - validation: invalid_mode / binary_not_absolute / image_tag_required /
 *     container_port_required / source_missing
 *   - host mode (β): timed-out → ok, immediate non-zero with ld error → fail,
 *     immediate zero exit → ok, spawn_error → fail with diagnostic
 *   - container mode: docker run → inspect → tcpProbe success path,
 *     connect fail → diagnostic gathered, keep_container_on_fail behaviour
 *   - reproduce_commands always present (success + fail)
 *   - missing_libs extraction from stderr patterns
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  createOmpSetupVerifyRuntimeTool,
  type AsyncSpawnFn,
  type AsyncSpawnResult,
  type TcpProbeFn,
} from "./omp-setup-verify-runtime"
import { FakeDockerRunner } from "../envsetup/fake-docker-runner"

const TOOL_CTX = {
  sessionID: "s",
  messageID: "m",
  abort: new AbortController().signal,
  metadata: () => {},
} as never

interface Harness {
  root: string
  binary: string
}

async function setupHarness(): Promise<Harness> {
  const root = await mkdtemp(join(tmpdir(), "omp-verify-test-"))
  const binary = join(root, "prob")
  await writeFile(binary, Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
  return { root, binary }
}

async function teardown(h: Harness): Promise<void> {
  await rm(h.root, { recursive: true, force: true })
}

function buildSpawn(result: AsyncSpawnResult): AsyncSpawnFn {
  return async () => result
}

function buf(s: string): Buffer {
  return Buffer.from(s, "utf-8")
}

const FAKE_INSPECT_JSON_WITH_PORT = (
  containerPort: number,
  hostPort: number,
): string =>
  JSON.stringify([
    {
      NetworkSettings: {
        Ports: {
          [`${containerPort}/tcp`]: [{ HostIp: "0.0.0.0", HostPort: String(hostPort) }],
        },
      },
    },
  ])

describe("omp_setup_verify_runtime", () => {
  let h: Harness

  beforeEach(async () => {
    h = await setupHarness()
  })
  afterEach(async () => {
    await teardown(h)
  })

  /* ── validation ─────────────────────────────────────────────────────── */

  test("rejects invalid mode", async () => {
    const t = createOmpSetupVerifyRuntimeTool({})
    const raw = await t.execute(
      { binary_path: h.binary, mode: "shell" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("invalid_mode")
  })

  test("rejects non-absolute binary_path", async () => {
    const t = createOmpSetupVerifyRuntimeTool({})
    const raw = await t.execute(
      { binary_path: "rel/path", mode: "host" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("binary_not_absolute")
  })

  test("container mode: image_tag required", async () => {
    const t = createOmpSetupVerifyRuntimeTool({})
    const raw = await t.execute(
      {
        binary_path: h.binary,
        mode: "container",
        container_port: 8080,
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("image_tag_required")
  })

  test("container mode: container_port required", async () => {
    const t = createOmpSetupVerifyRuntimeTool({})
    const raw = await t.execute(
      {
        binary_path: h.binary,
        mode: "container",
        image_tag: "omp-abc123",
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("container_port_required")
  })

  /* ── host mode (β process spawn) ────────────────────────────────────── */

  test("host: timeout → ok (ld resolved, binary blocked on stdin)", async () => {
    const t = createOmpSetupVerifyRuntimeTool({
      processSpawn: buildSpawn({
        exit_code: null,
        signal: "SIGTERM",
        stdout: buf(""),
        stderr: buf(""),
        timed_out: true,
      }),
    })
    const raw = await t.execute(
      { binary_path: h.binary, mode: "host" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(true)
    expect(out.mode).toBe("host")
    expect(out.evidence.timed_out).toBe(true)
    expect(Array.isArray(out.reproduce_commands)).toBe(true)
    expect(out.reproduce_commands.some((c: string) => c.startsWith("ldd "))).toBe(true)
  })

  test("host: immediate zero exit → ok (small binary OK case)", async () => {
    const t = createOmpSetupVerifyRuntimeTool({
      processSpawn: buildSpawn({
        exit_code: 0,
        signal: null,
        stdout: buf("output"),
        stderr: buf(""),
        timed_out: false,
      }),
    })
    const raw = await t.execute(
      { binary_path: h.binary, mode: "host" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(true)
    expect(out.evidence.exit_code).toBe(0)
    expect(out.evidence.missing_libs).toEqual([])
  })

  test("host: ld error 'cannot open shared object file' → fail with missing_libs", async () => {
    const t = createOmpSetupVerifyRuntimeTool({
      processSpawn: buildSpawn({
        exit_code: 127,
        signal: null,
        stdout: buf(""),
        stderr: buf(
          "./prob: error while loading shared libraries: libz.so.1: cannot open shared object file: No such file or directory\n",
        ),
        timed_out: false,
      }),
    })
    const raw = await t.execute(
      { binary_path: h.binary, mode: "host" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.evidence.missing_libs).toContain("libz.so.1")
    expect(out.evidence.exit_code).toBe(127)
  })

  test("host: spawn_error (ENOENT) → fail with spawn_error in evidence", async () => {
    const t = createOmpSetupVerifyRuntimeTool({
      processSpawn: buildSpawn({
        exit_code: null,
        signal: null,
        stdout: buf(""),
        stderr: buf(""),
        timed_out: false,
        spawn_error: { code: "ENOENT", message: "spawn ENOENT" },
      }),
    })
    const raw = await t.execute(
      { binary_path: h.binary, mode: "host" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.evidence.spawn_error?.code).toBe("ENOENT")
  })

  test("host: source_missing when binary_path does not exist", async () => {
    const t = createOmpSetupVerifyRuntimeTool({})
    const raw = await t.execute(
      { binary_path: join(h.root, "nope"), mode: "host" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("source_missing")
  })

  /* ── container mode ─────────────────────────────────────────────────── */

  test("container: tcp probe success → ok with host_port + reproduce_commands", async () => {
    const runner = new FakeDockerRunner((call) => {
      if (call.args[0] === "run") {
        return { exitCode: 0, stdout: "fake-cid-abc\n" }
      }
      if (call.args[0] === "inspect") {
        return { exitCode: 0, stdout: FAKE_INSPECT_JSON_WITH_PORT(8080, 32768) }
      }
      if (call.args[0] === "stop") {
        return { exitCode: 0 }
      }
      return { exitCode: 0 }
    })
    const probe: TcpProbeFn = async () => true

    const t = createOmpSetupVerifyRuntimeTool({ runner, tcpProbe: probe })
    const raw = await t.execute(
      {
        binary_path: h.binary,
        mode: "container",
        image_tag: "omp-abc",
        container_binary_path: "/home/ctf/prob",
        container_port: 8080,
        timeout_ms: 1000,
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)

    expect(out.ok).toBe(true)
    expect(out.mode).toBe("container")
    expect(out.evidence.host_port).toBe(32768)
    expect(out.evidence.container_port).toBe(8080)
    expect(out.reproduce_commands.some((c: string) => c.startsWith("docker run"))).toBe(true)
    expect(out.reproduce_commands.some((c: string) => c.includes("nc 127.0.0.1 32768"))).toBe(true)

    // cleanup: docker stop should have been called
    expect(runner.calls.some((c) => c.args[0] === "stop")).toBe(true)
  })

  test("container: tcp probe fail → diagnostic gathered (docker logs + state)", async () => {
    const runner = new FakeDockerRunner((call) => {
      if (call.args[0] === "run") {
        return { exitCode: 0, stdout: "fake-cid-fail\n" }
      }
      if (call.args[0] === "inspect" && call.args[1] === "fake-cid-fail" && call.args.length === 2) {
        return { exitCode: 0, stdout: FAKE_INSPECT_JSON_WITH_PORT(8080, 32769) }
      }
      if (call.args[0] === "inspect" && call.args[1] === "-f") {
        // inspect with format string for State.Status
        return { exitCode: 0, stdout: "exited\n" }
      }
      if (call.args[0] === "logs") {
        return {
          exitCode: 0,
          stdout: "challenge crashed: segfault\n",
          stderr: "ld: missing libfoo.so.1\n",
        }
      }
      if (call.args[0] === "stop") {
        return { exitCode: 0 }
      }
      return { exitCode: 0 }
    })
    const probe: TcpProbeFn = async () => false

    const t = createOmpSetupVerifyRuntimeTool({ runner, tcpProbe: probe })
    const raw = await t.execute(
      {
        binary_path: h.binary,
        mode: "container",
        image_tag: "omp-abc",
        container_port: 8080,
        timeout_ms: 400,  // short — quickly hits "fail"
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)

    expect(out.ok).toBe(false)
    expect(out.evidence.container_state).toBe("exited")
    expect(out.evidence.docker_logs_head).toContain("challenge crashed")
    expect(out.evidence.kept_for_debug).toBe(false)
    // cleanup: docker stop should still have been called
    expect(runner.calls.some((c) => c.args[0] === "stop")).toBe(true)
  })

  test("container: keep_container_on_fail=true → container NOT stopped + reproduce shows docker exec", async () => {
    const runner = new FakeDockerRunner((call) => {
      if (call.args[0] === "run") {
        return { exitCode: 0, stdout: "fake-cid-keep\n" }
      }
      if (call.args[0] === "inspect" && call.args.length === 2) {
        return { exitCode: 0, stdout: FAKE_INSPECT_JSON_WITH_PORT(8080, 32770) }
      }
      if (call.args[0] === "inspect" && call.args[1] === "-f") {
        return { exitCode: 0, stdout: "running\n" }
      }
      if (call.args[0] === "logs") {
        return { exitCode: 0, stdout: "", stderr: "" }
      }
      if (call.args[0] === "stop") {
        return { exitCode: 0 }
      }
      return { exitCode: 0 }
    })
    const probe: TcpProbeFn = async () => false

    const t = createOmpSetupVerifyRuntimeTool({ runner, tcpProbe: probe })
    const raw = await t.execute(
      {
        binary_path: h.binary,
        mode: "container",
        image_tag: "omp-abc",
        container_port: 8080,
        timeout_ms: 400,
        keep_container_on_fail: true,
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)

    expect(out.ok).toBe(false)
    expect(out.evidence.kept_for_debug).toBe(true)
    expect(out.reproduce_commands.some((c: string) => c.startsWith("docker exec -it"))).toBe(true)
    expect(
      out.reproduce_commands.some((c: string) => c.startsWith("docker stop")),
    ).toBe(true)

    // cleanup: docker stop must NOT have been called by the tool
    expect(runner.calls.some((c) => c.args[0] === "stop")).toBe(false)
  })

  test("container: docker run failure → docker-run-failed typed error", async () => {
    const runner = new FakeDockerRunner((call) => {
      if (call.args[0] === "run") {
        return { exitCode: 125, stderr: "image not found" }
      }
      return { exitCode: 0 }
    })
    const probe: TcpProbeFn = async () => false

    const t = createOmpSetupVerifyRuntimeTool({ runner, tcpProbe: probe })
    const raw = await t.execute(
      {
        binary_path: h.binary,
        mode: "container",
        image_tag: "missing-image",
        container_port: 8080,
      },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("docker-run-failed")
  })

  /* ── missing_libs extraction patterns ────────────────────────────────── */

  test("missing_libs: 'libfoo.so.1 => not found' pattern (ldd output)", async () => {
    const t = createOmpSetupVerifyRuntimeTool({
      processSpawn: buildSpawn({
        exit_code: 1,
        signal: null,
        stdout: buf(""),
        stderr: buf(
          "libz.so.1 => not found\nliblzma.so.5 => not found\nlibm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x7f...)\n",
        ),
        timed_out: false,
      }),
    })
    const raw = await t.execute(
      { binary_path: h.binary, mode: "host" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.evidence.missing_libs).toContain("libz.so.1")
    expect(out.evidence.missing_libs).toContain("liblzma.so.5")
    // libm.so.6 is resolved, not missing
    expect(out.evidence.missing_libs).not.toContain("libm.so.6")
  })
})
