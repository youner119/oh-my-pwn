import { describe, expect, test } from "bun:test"
import { createOmpPwnoStatusTool } from "./container-tool"

function makeMcpFetch(pwnoStatus?: string): typeof fetch {
  return (async () => {
    return new Response(
      pwnoStatus
        ? JSON.stringify({ pwno: { status: pwnoStatus } })
        : JSON.stringify({}),
      { status: 200, headers: { "content-type": "application/json" } },
    )
  }) as unknown as typeof fetch
}

const PWNO_URL = "http://127.0.0.1:5500/mcp"
const SERVER_URL = "http://localhost:4096"
const WORKSPACE = "/home/u/oh-my-pwn/workspace"

describe("omp_pwno_status", () => {
  test("healthy when container reachable and mcp connected", async () => {
    const t = createOmpPwnoStatusTool({
      pwnoUrl: PWNO_URL,
      serverUrl: SERVER_URL,
      workspacePath: WORKSPACE,
      probe: async () => true,
      fetchImpl: makeMcpFetch("connected"),
    })
    const raw = await t.execute({}, { sessionID: "s", messageID: "m", abort: new AbortController().signal, metadata: () => {} } as never)
    const out = JSON.parse(raw as string)
    expect(out.healthy).toBe(true)
    expect(out.container_reachable).toBe(true)
    expect(out.mcp_status).toBe("connected")
    expect(out.hint).toBeUndefined()
  })

  test("container down → hint contains docker run command and workspace path", async () => {
    const t = createOmpPwnoStatusTool({
      pwnoUrl: PWNO_URL,
      serverUrl: SERVER_URL,
      workspacePath: WORKSPACE,
      probe: async () => false,
      fetchImpl: makeMcpFetch(undefined),
    })
    const raw = await t.execute({}, { sessionID: "s", messageID: "m", abort: new AbortController().signal, metadata: () => {} } as never)
    const out = JSON.parse(raw as string)
    expect(out.healthy).toBe(false)
    expect(out.container_reachable).toBe(false)
    expect(out.hint).toContain("docker run")
    expect(out.hint).toContain(WORKSPACE)
    expect(out.hint).toContain("ghcr.io/pwno-io/pwno-mcp")
  })

  test("container up but mcp not connected → hint suggests reconnect", async () => {
    const t = createOmpPwnoStatusTool({
      pwnoUrl: PWNO_URL,
      serverUrl: SERVER_URL,
      workspacePath: WORKSPACE,
      probe: async () => true,
      fetchImpl: makeMcpFetch("found"),
    })
    const raw = await t.execute({}, { sessionID: "s", messageID: "m", abort: new AbortController().signal, metadata: () => {} } as never)
    const out = JSON.parse(raw as string)
    expect(out.healthy).toBe(false)
    expect(out.container_reachable).toBe(true)
    expect(out.mcp_status).toBe("found")
    expect(out.hint).toContain("/mcp/pwno/connect")
  })

  test("mcp_status defaults to not_registered when pwno key absent", async () => {
    const t = createOmpPwnoStatusTool({
      pwnoUrl: PWNO_URL,
      serverUrl: SERVER_URL,
      workspacePath: WORKSPACE,
      probe: async () => true,
      fetchImpl: makeMcpFetch(undefined),
    })
    const raw = await t.execute({}, { sessionID: "s", messageID: "m", abort: new AbortController().signal, metadata: () => {} } as never)
    const out = JSON.parse(raw as string)
    expect(out.mcp_status).toBe("not_registered")
  })

  test("no serverUrl → mcp_status stays unknown", async () => {
    const t = createOmpPwnoStatusTool({
      pwnoUrl: PWNO_URL,
      workspacePath: WORKSPACE,
      probe: async () => true,
    })
    const raw = await t.execute({}, { sessionID: "s", messageID: "m", abort: new AbortController().signal, metadata: () => {} } as never)
    const out = JSON.parse(raw as string)
    expect(out.container_reachable).toBe(true)
    expect(out.mcp_status).toBe("unknown")
    expect(out.healthy).toBe(false)
  })
})
