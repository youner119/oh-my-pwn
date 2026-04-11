/**
 * In-memory {@link GhidraMcpClient} implementation used exclusively by unit
 * tests. NOT exported from `index.ts`; production code never imports it.
 *
 * Tests construct a {@link FakeGhidraMcpClient} with a responder function
 * that pattern-matches on the tool name and arguments and returns a canned
 * response. Every call is also recorded in {@link FakeGhidraMcpClient.calls}
 * so tests can assert that the correct sequence of tool invocations occurred.
 *
 * Usage example:
 *
 *   const client = new FakeGhidraMcpClient(
 *     (call) => {
 *       if (call.name === "listFunctions") {
 *         return { content: [{ type: "text", text: '["main","sub_1234"]' }] }
 *       }
 *       if (call.name === "decompileFunction") {
 *         return { content: [{ type: "text", text: "void main() {}" }] }
 *       }
 *       throw new Error(`unexpected tool call: ${call.name}`)
 *     },
 *     [{ name: "listFunctions" }, { name: "decompileFunction" }],
 *   )
 *
 * @internal
 */

import { GhidraBridgeError } from "./errors.js"
import type {
  GhidraMcpClient,
  GhidraMcpConfig,
  McpToolCallResult,
  McpToolInfo,
} from "./types.js"

export interface FakeToolCall {
  name: string
  args: Record<string, unknown>
}

export interface FakeToolResponse {
  content?: Array<{ type: string; text?: string }>
  isError?: boolean
  /**
   * If set, the fake throws this error instead of returning a result. Used to
   * simulate server-side failures.
   */
  throwError?: GhidraBridgeError
}

export type FakeToolResponder = (call: FakeToolCall) => FakeToolResponse

export class FakeGhidraMcpClient implements GhidraMcpClient {
  /** Ordered record of every tool invocation, for test assertions. */
  readonly calls: FakeToolCall[] = []

  private connected = false
  private tools: McpToolInfo[]

  constructor(
    private readonly responder: FakeToolResponder,
    availableTools?: McpToolInfo[],
  ) {
    this.tools = availableTools ?? []
  }

  async connect(_config: GhidraMcpConfig): Promise<void> {
    this.connected = true
  }

  async disconnect(): Promise<void> {
    this.connected = false
  }

  isConnected(): boolean {
    return this.connected
  }

  async listTools(): Promise<McpToolInfo[]> {
    return this.tools
  }

  async callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<McpToolCallResult> {
    const call: FakeToolCall = { name, args }
    this.calls.push(call)
    const response = this.responder(call)
    if (response.throwError !== undefined) {
      throw response.throwError
    }
    return {
      content: response.content ?? [],
      isError: response.isError,
    }
  }
}
