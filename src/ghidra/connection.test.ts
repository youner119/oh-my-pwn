import { describe, expect, test } from "bun:test"
import { GhidraBridgeError } from "./errors"
import { FakeGhidraMcpClient } from "./fake-client"
import type { GhidraMcpClient, GhidraMcpConfig } from "./types"
import type { HeadlessConfig, HeadlessResult } from "./headless"
import { connectToGhidra } from "./connection"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const STDIO_CONFIG: GhidraMcpConfig = {
  type: "stdio",
  command: "python",
  args: ["bridge_mcp_ghidra.py"],
}

/** FakeGhidraMcpClient that succeeds on connect and health check. */
function makeHealthyFake(): FakeGhidraMcpClient {
  return new FakeGhidraMcpClient(
    (_call) => ({ content: [{ type: "text", text: "OK" }] }),
    [{ name: "check_connection" }],
  )
}

/** FakeGhidraMcpClient that throws on connect. */
function makeFailingFake(): FakeGhidraMcpClient {
  const fake = new FakeGhidraMcpClient((_call) => ({ content: [] }))
  // Override connect to throw a connection-failed error.
  ;(fake as unknown as { connect(cfg: GhidraMcpConfig): Promise<void> }).connect =
    async (_cfg: GhidraMcpConfig): Promise<void> => {
      throw new GhidraBridgeError({
        kind: "connection-failed",
        transport: "sse",
        message: "ECONNREFUSED",
        code: "ECONNREFUSED",
      })
    }
  return fake
}

/** Headless stubs: no-op import + stdio config. */
const stubHeadlessImport = (
  _binaryPath: string,
  _config?: HeadlessConfig,
): HeadlessResult => ({
  projectPath: "/tmp/ghidra-project",
  projectName: "omp-chall",
  freshImport: true,
})

const stubHeadlessConfig = (_config?: HeadlessConfig): GhidraMcpConfig =>
  STDIO_CONFIG

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("connectToGhidra", () => {
  test("connects to GUI when available", async () => {
    const guiClient = makeHealthyFake()

    const conn = await connectToGhidra({
      binaryPath: "/tmp/chall",
      createClient: () => guiClient,
      runHeadlessImport: stubHeadlessImport,
      buildHeadlessMcpConfig: stubHeadlessConfig,
    })

    expect(conn.mode).toBe("gui")
    expect(conn.client).toBe(guiClient)
    expect(conn.client.isConnected()).toBe(true)
  })

  test("falls back to headless when GUI connect throws", async () => {
    let callCount = 0
    const guiFake = makeFailingFake()
    const headlessFake = makeHealthyFake()

    const conn = await connectToGhidra({
      binaryPath: "/tmp/chall",
      createClient: () => {
        callCount++
        // First call → GUI (will fail), second call → headless (succeeds).
        return callCount === 1 ? guiFake : headlessFake
      },
      runHeadlessImport: stubHeadlessImport,
      buildHeadlessMcpConfig: stubHeadlessConfig,
    })

    expect(conn.mode).toBe("headless")
    expect(callCount).toBe(2)
    expect(conn.client.isConnected()).toBe(true)
  })

  test("falls back to headless when GUI succeeds connect but health check fails", async () => {
    // A client that connects but whose health check returns isError: true.
    const unhealthyGui = new FakeGhidraMcpClient(
      (_call) => ({ isError: true, content: [] }),
    )
    let callCount = 0
    const headlessFake = makeHealthyFake()

    const conn = await connectToGhidra({
      binaryPath: "/tmp/chall",
      createClient: () => {
        callCount++
        return callCount === 1 ? unhealthyGui : headlessFake
      },
      runHeadlessImport: stubHeadlessImport,
      buildHeadlessMcpConfig: stubHeadlessConfig,
    })

    expect(conn.mode).toBe("headless")
  })

  test("disconnect calls client.disconnect", async () => {
    const guiClient = makeHealthyFake()

    const conn = await connectToGhidra({
      binaryPath: "/tmp/chall",
      createClient: () => guiClient,
      runHeadlessImport: stubHeadlessImport,
      buildHeadlessMcpConfig: stubHeadlessConfig,
    })

    expect(conn.client.isConnected()).toBe(true)
    await conn.disconnect()
    expect(conn.client.isConnected()).toBe(false)
  })

  test("ensureConnected reconnects if client has been disconnected", async () => {
    let callCount = 0
    const firstClient = makeHealthyFake()
    const secondClient = makeHealthyFake()

    const conn = await connectToGhidra({
      binaryPath: "/tmp/chall",
      createClient: () => {
        callCount++
        return callCount === 1 ? firstClient : secondClient
      },
      runHeadlessImport: stubHeadlessImport,
      buildHeadlessMcpConfig: stubHeadlessConfig,
    })

    // Manually disconnect without going through conn.disconnect().
    await firstClient.disconnect()
    expect(conn.client.isConnected()).toBe(false)

    // ensureConnected should replace the client and reconnect.
    await conn.ensureConnected()
    expect(conn.client.isConnected()).toBe(true)
    expect(callCount).toBe(2)
  })

  test("ensureConnected is a no-op when already connected", async () => {
    let callCount = 0
    const guiClient = makeHealthyFake()

    const conn = await connectToGhidra({
      binaryPath: "/tmp/chall",
      createClient: () => {
        callCount++
        return guiClient
      },
      runHeadlessImport: stubHeadlessImport,
      buildHeadlessMcpConfig: stubHeadlessConfig,
    })

    // Already connected — ensureConnected should not create another client.
    await conn.ensureConnected()
    expect(callCount).toBe(1)
    expect(conn.client.isConnected()).toBe(true)
  })

  test("throws connection-failed when both GUI and headless fail", async () => {
    // headless import stub throws so both paths fail.
    const failingHeadlessImport = (
      _binaryPath: string,
      _config?: HeadlessConfig,
    ): HeadlessResult => {
      throw new GhidraBridgeError({
        kind: "server-error",
        message: "analyzeHeadless exited with code 1",
      })
    }

    let thrown: unknown
    try {
      await connectToGhidra({
        binaryPath: "/tmp/chall",
        createClient: makeFailingFake,
        runHeadlessImport: failingHeadlessImport,
        buildHeadlessMcpConfig: stubHeadlessConfig,
      })
    } catch (err) {
      thrown = err
    }

    expect(thrown).toBeInstanceOf(GhidraBridgeError)
    expect((thrown as GhidraBridgeError).kind).toBe("connection-failed")
  })
})
