/**
 * T06 — ghidra-mcp bridge type definitions.
 *
 * All types used by the ghidra-mcp bridge module. The bridge connects OmP to
 * an external ghidra-mcp MCP server and provides typed wrappers for the
 * Reverser agent (T07) to consume.
 *
 * The client interface ({@link GhidraMcpClient}) follows the DI seam pattern
 * established by {@link import("../envsetup/docker-runner").DockerRunner}:
 * a real implementation wraps `@modelcontextprotocol/sdk` Client, and a fake
 * is injected in tests.
 */

// ---------------------------------------------------------------------------
// Connection configuration
// ---------------------------------------------------------------------------

/** How OmP connects to the ghidra-mcp server. */
export interface GhidraMcpConfig {
  /**
   * Transport type.
   * - "stdio": launches the server as a child process.
   * - "http": streamable HTTP (used by Ghidra GUI MCP plugin, default port 8089).
   * - "sse": Server-Sent Events (deprecated by bethington/ghidra-mcp).
   */
  type: "stdio" | "http" | "sse"

  // --- stdio fields ---
  /** Command to launch the ghidra-mcp server (e.g. "ghidra-mcp-server"). */
  command?: string
  /** Arguments passed to the command. */
  args?: string[]
  /** Extra environment variables for the spawned process. */
  env?: Record<string, string>

  // --- sse fields ---
  /** Server URL for SSE transport (e.g. "http://localhost:8080/sse"). */
  url?: string

  /** Connection timeout in milliseconds. Default 30 000. */
  timeoutMs?: number
}

// ---------------------------------------------------------------------------
// Ghidra analysis result types
// ---------------------------------------------------------------------------

/** A function discovered by Ghidra analysis. */
export interface GhidraFunction {
  name: string
  /** Hex address string, e.g. "0x00401000". */
  address: string
  /** Size in bytes, if Ghidra reports it. */
  size?: number
  /** True for import stubs / thunks. */
  isThunk?: boolean
  /** True for external / library functions. */
  isExternal?: boolean
}

/** Decompilation result for a single function. */
export interface GhidraDecompilation {
  functionName: string
  address: string
  /** Decompiled C-like pseudo-code. */
  code: string
}

/** A string reference found in the binary. */
export interface GhidraString {
  address: string
  value: string
  /** Section name (e.g. ".rodata", ".data"). */
  section?: string
}

/** An imported symbol. */
export interface GhidraImport {
  name: string
  /** Shared library providing this symbol (e.g. "libc.so.6"). */
  library?: string
  address?: string
}

/** An exported symbol. */
export interface GhidraExport {
  name: string
  address: string
}

/** A cross-reference entry. */
export interface GhidraXref {
  fromAddress: string
  toAddress: string
  /** Reference type as reported by Ghidra (e.g. "CALL", "DATA", "READ"). */
  refType: string
  /** Function containing the source address, if resolved. */
  fromFunction?: string
}

// ---------------------------------------------------------------------------
// Structural summary (composed from multiple tool calls)
// ---------------------------------------------------------------------------

/**
 * A structural summary of the binary, produced by composing multiple
 * ghidra-mcp tool calls. This is the main output the Reverser agent writes
 * into the journal.
 */
export interface GhidraStructuralSummary {
  /** All discovered functions (may be large — caller should trim for journal). */
  functions: GhidraFunction[]
  /** Imported symbols — key signal for VulnHunter (dangerous calls). */
  imports: GhidraImport[]
  /** Exported symbols. */
  exports: GhidraExport[]
  /** Interesting strings (filtered by bridge heuristics). */
  strings: GhidraString[]
  /** Functions whose names or bodies match known-dangerous patterns. */
  dangerousCalls: DangerousCallEntry[]
}

/**
 * An invocation of a known-dangerous function (e.g. `gets`, `printf` with
 * user-controlled format, `free` without null-check).
 */
export interface DangerousCallEntry {
  /** The dangerous function name (e.g. "gets", "printf", "system"). */
  callee: string
  /** The function that calls the dangerous function. */
  caller: string
  callerAddress: string
  /** Why this is flagged. */
  reason: string
}

// ---------------------------------------------------------------------------
// On-disk analysis file (written by Reverser, read by VulnHunter et al.)
// ---------------------------------------------------------------------------

/**
 * The Reverser agent writes this structure to
 * `<challenge-dir>/.omp/artifacts/reverser-analysis.json`.
 *
 * Downstream agents (VulnHunter, Exploiter) read this file to access
 * decompilations, function addresses (for breakpoints), and dangerous call
 * info without needing a live ghidra-mcp connection.
 */
export interface ReverserAnalysis {
  /** All discovered functions (full map with addresses). */
  functions: GhidraFunction[]
  /**
   * Full decompilation results keyed by address.
   * Only "key" user-defined functions are decompiled — the Reverser AI
   * decides which by following entry → main → callees, skipping externals.
   */
  decompilations: Record<string, GhidraDecompilation>
  /** Imported symbols. */
  imports: GhidraImport[]
  /** Exported symbols. */
  exports: GhidraExport[]
  /** Dangerous function call sites identified by cross-reference analysis. */
  dangerousCalls: DangerousCallEntry[]
  /** When this analysis was produced. */
  analyzedAt: string
}

// ---------------------------------------------------------------------------
// MCP client abstraction (DI seam)
// ---------------------------------------------------------------------------

/** Raw result from an MCP tool call, mirroring the MCP protocol shape. */
export interface McpToolCallResult {
  content: McpContentBlock[]
  isError?: boolean
}

export interface McpContentBlock {
  type: string
  text?: string
  [key: string]: unknown
}

/** Descriptor for a tool exposed by the ghidra-mcp server. */
export interface McpToolInfo {
  name: string
  description?: string
}

/**
 * Abstract client interface for ghidra-mcp communication.
 *
 * The real implementation (`RealGhidraMcpClient` in `client.ts`) wraps the
 * `@modelcontextprotocol/sdk` Client. Tests inject a
 * `FakeGhidraMcpClient` (see `fake-client.ts`) that returns canned data.
 *
 * The interface is async because MCP communication involves I/O
 * (stdio pipes or HTTP/SSE).
 */
export interface GhidraMcpClient {
  /** Connect to the ghidra-mcp server. */
  connect(config: GhidraMcpConfig): Promise<void>
  /** Disconnect gracefully. */
  disconnect(): Promise<void>
  /** Whether the client is currently connected. */
  isConnected(): boolean
  /** List tools exposed by the server. */
  listTools(): Promise<McpToolInfo[]>
  /** Call a named tool with the given arguments. */
  callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<McpToolCallResult>
}
