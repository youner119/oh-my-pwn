/**
 * Real {@link GhidraMcpClient} implementation backed by
 * `@modelcontextprotocol/sdk`.
 *
 * The interface is defined in `./types.ts`. Tests inject a
 * {@link import("./fake-client").FakeGhidraMcpClient} instead of this class
 * so ghidra-mcp communication can be exercised without a live server.
 *
 * Usage:
 *
 *   const client = createGhidraMcpClient()
 *   await client.connect({ type: "stdio", command: "ghidra-mcp-server" })
 *   const tools = await client.listTools()
 *   const result = await client.callTool("decompileFunction", { name: "main" })
 *   await client.disconnect()
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js"
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js"
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js"
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js"
import { GhidraBridgeError } from "./errors.js"
import type {
  GhidraMcpClient,
  GhidraMcpConfig,
  McpToolCallResult,
  McpToolInfo,
} from "./types.js"

const CLIENT_INFO = { name: "omp-ghidra-bridge", version: "1.0.0" } as const

/**
 * Real ghidra-mcp client backed by `@modelcontextprotocol/sdk`.
 *
 * Never import this class directly in production code; use
 * {@link createGhidraMcpClient} so future implementations can be swapped.
 */
class RealGhidraMcpClient implements GhidraMcpClient {
  private client: Client | null = null
  private connected = false
  private timeoutMs = 30_000

  /** Connect to the ghidra-mcp server using the given config. */
  async connect(config: GhidraMcpConfig): Promise<void> {
    // Validate config before attempting any I/O.
    if (config.type === "stdio" && !config.command) {
      throw new GhidraBridgeError({
        kind: "not-configured",
        message: 'GhidraMcpConfig.type is "stdio" but command is missing',
        field: "command",
      })
    }
    if ((config.type === "sse" || config.type === "http") && !config.url) {
      throw new GhidraBridgeError({
        kind: "not-configured",
        message: `GhidraMcpConfig.type is "${config.type}" but url is missing`,
        field: "url",
      })
    }

    this.timeoutMs = config.timeoutMs ?? 30_000

    let transport: Transport
    if (config.type === "stdio") {
      transport = new StdioClientTransport({
        command: config.command!,
        args: config.args ?? [],
        env: { ...process.env, ...config.env } as Record<string, string>,
      })
    } else if (config.type === "http") {
      transport = new StreamableHTTPClientTransport(new URL(config.url!))
    } else {
      transport = new SSEClientTransport(new URL(config.url!))
    }

    const client = new Client(CLIENT_INFO, {})

    try {
      await client.connect(transport)
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code
      throw new GhidraBridgeError({
        kind: "connection-failed",
        message: `Failed to connect to ghidra-mcp server (${config.type}): ${String(err)}`,
        transport: config.type,
        code,
      })
    }

    this.client = client
    this.connected = true
  }

  /** Disconnect gracefully. Errors from close() are swallowed. */
  async disconnect(): Promise<void> {
    if (this.client === null) {
      return
    }
    try {
      await this.client.close()
    } catch {
      // Swallow — the server may already be gone.
    } finally {
      this.client = null
      this.connected = false
    }
  }

  /** Whether the client is currently connected. */
  isConnected(): boolean {
    return this.connected && this.client !== null
  }

  /** List tools exposed by the ghidra-mcp server. */
  async listTools(): Promise<McpToolInfo[]> {
    this.assertConnected()
    const result = await this.client!.listTools()
    return result.tools.map((t) => ({
      name: t.name,
      description: t.description,
    }))
  }

  /** Call a named tool with the given arguments. */
  async callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<McpToolCallResult> {
    this.assertConnected()
    const result = await this.client!.callTool({ name, arguments: args })
    return {
      content: (result.content ?? []) as McpToolCallResult["content"],
      isError: result.isError as boolean | undefined,
    }
  }

  private assertConnected(): void {
    if (!this.isConnected()) {
      throw new GhidraBridgeError({
        kind: "connection-closed",
        message:
          "GhidraMcpClient is not connected; call connect() before calling this method",
      })
    }
  }
}

/**
 * Factory function for the real ghidra-mcp client.
 *
 * Prefer this over `new RealGhidraMcpClient()` so tests can inject a
 * {@link import("./fake-client").FakeGhidraMcpClient} at the call site.
 */
export function createGhidraMcpClient(): GhidraMcpClient {
  return new RealGhidraMcpClient()
}
