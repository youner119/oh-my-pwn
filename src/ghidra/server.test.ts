import { describe, expect, test } from "bun:test"
import { GhidraBridgeError } from "./errors"
import { FakeGhidraMcpClient } from "./fake-client"
import type { GhidraMcpConfig } from "./types"
import {
  checkGhidraHealth,
  createDefaultGhidraConfig,
  getGhidraMetadata,
  listGhidraTools,
} from "./server"

const STDIO_CONFIG: GhidraMcpConfig = {
  type: "stdio",
  command: "python",
  args: ["bridge_mcp_ghidra.py"],
}

async function connectedFake(
  responder: ConstructorParameters<typeof FakeGhidraMcpClient>[0],
  availableTools?: ConstructorParameters<typeof FakeGhidraMcpClient>[1],
): Promise<FakeGhidraMcpClient> {
  const client = new FakeGhidraMcpClient(responder, availableTools)
  await client.connect(STDIO_CONFIG)
  return client
}

describe("checkGhidraHealth", () => {
  test("returns true when check_connection succeeds", async () => {
    const client = await connectedFake((_call) => ({
      content: [{ type: "text", text: "OK" }],
    }))
    expect(await checkGhidraHealth(client)).toBe(true)
  })

  test("returns false when check_connection returns isError", async () => {
    const client = await connectedFake((_call) => ({
      isError: true,
      content: [],
    }))
    expect(await checkGhidraHealth(client)).toBe(false)
  })

  test("returns false when client throws", async () => {
    const client = await connectedFake((_call) => ({
      throwError: new GhidraBridgeError({
        kind: "server-error",
        message: "server crashed",
      }),
    }))
    expect(await checkGhidraHealth(client)).toBe(false)
  })

  test("returns false when client is not connected", async () => {
    const client = new FakeGhidraMcpClient((_call) => ({
      content: [{ type: "text", text: "OK" }],
    }))
    // Deliberately NOT calling connect() — client.isConnected() === false
    expect(await checkGhidraHealth(client)).toBe(false)
  })
})

describe("getGhidraMetadata", () => {
  test("parses JSON metadata response", async () => {
    const meta = {
      programName: "chall",
      languageId: "x86:LE:64:default",
      compilerSpec: "gcc",
      addressSize: 64,
      executableFormat: "ELF",
    }
    const client = await connectedFake((_call) => ({
      content: [{ type: "text", text: JSON.stringify(meta) }],
    }))
    const result = await getGhidraMetadata(client)
    expect(result).not.toBeNull()
    expect(result?.programName).toBe("chall")
    expect(result?.languageId).toBe("x86:LE:64:default")
    expect(result?.compilerSpec).toBe("gcc")
    expect(result?.addressSize).toBe(64)
    expect(result?.executableFormat).toBe("ELF")
  })

  test("returns null when call fails", async () => {
    const client = await connectedFake((_call) => ({
      throwError: new GhidraBridgeError({
        kind: "tool-call-failed",
        message: "tool failed",
        toolName: "getProgramInfo",
      }),
    }))
    expect(await getGhidraMetadata(client)).toBeNull()
  })
})

describe("listGhidraTools", () => {
  test("returns tool list from client", async () => {
    const tools = [
      { name: "listFunctions", description: "List all functions" },
      { name: "decompileFunction", description: "Decompile a function" },
    ]
    const client = await connectedFake((_call) => ({ content: [] }), tools)
    const result = await listGhidraTools(client)
    expect(result).toEqual(tools)
  })
})

describe("createDefaultGhidraConfig", () => {
  test("returns stdio config with python command", () => {
    const config = createDefaultGhidraConfig()
    expect(config.type).toBe("stdio")
    expect(config.command).toBe("python")
    expect(Array.isArray(config.args)).toBe(true)
    expect(config.args).toContain("bridge_mcp_ghidra.py")
  })
})
