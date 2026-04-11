/**
 * T06 — ghidra-mcp server lifecycle helpers.
 *
 * Provides convenience functions for launching and interrogating a
 * ghidra-mcp server instance. The Reverser agent (T07) talks to ghidra-mcp
 * directly via MCP tools; this module handles the before/after — connecting,
 * health-checking, and tool discovery — so the Orchestrator can gate on
 * readiness before handing control to the agent.
 */

import { createGhidraMcpClient } from "./client.js"
import { GhidraBridgeError } from "./errors.js"
import type { GhidraMcpClient, GhidraMcpConfig, McpToolInfo } from "./types.js"

// ---------------------------------------------------------------------------
// Exported types
// ---------------------------------------------------------------------------

/**
 * Metadata reported by the ghidra-mcp server about the currently-open
 * program. All fields are optional because the server may omit any of them
 * depending on ghidra-mcp version and whether a program is loaded.
 */
export interface GhidraServerMetadata {
  programName?: string
  languageId?: string
  compilerSpec?: string
  addressSize?: number
  executableFormat?: string
  [key: string]: unknown
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Create a client, connect it to the ghidra-mcp server, and return the
 * connected client.
 *
 * This is the primary entry point for OmP subsystems that need a live
 * ghidra-mcp connection. If the connection fails, the {@link GhidraBridgeError}
 * thrown by {@link GhidraMcpClient.connect} propagates unchanged.
 *
 * @param config - Transport and timeout settings for the server.
 * @returns A connected {@link GhidraMcpClient}.
 */
export async function launchGhidraServer(
  config: GhidraMcpConfig,
): Promise<GhidraMcpClient> {
  const client = createGhidraMcpClient()
  await client.connect(config)
  return client
}

/**
 * Probe the server with a lightweight `check_connection` tool call.
 *
 * Returns `true` when the call succeeds and the server reports no error.
 * Returns `false` (without throwing) in every other case:
 * - the client is not connected
 * - `callTool` throws any error
 * - the tool result carries `isError: true`
 *
 * @param client - A (possibly disconnected) {@link GhidraMcpClient}.
 * @returns `true` if the server is reachable and healthy.
 */
export async function checkGhidraHealth(
  client: GhidraMcpClient,
): Promise<boolean> {
  if (!client.isConnected()) {
    return false
  }
  try {
    const result = await client.callTool("check_connection", {})
    return result.isError !== true
  } catch {
    return false
  }
}

/**
 * Retrieve program metadata from the ghidra-mcp server.
 *
 * Calls `get_metadata` and parses the first text content block as JSON.
 * Returns `null` — without throwing — if the call fails, returns no text
 * content, or the content is not valid JSON. Non-fatal: callers should treat
 * `null` as "metadata unavailable" and continue.
 *
 * @param client - A connected {@link GhidraMcpClient}.
 * @returns Parsed {@link GhidraServerMetadata}, or `null` on any failure.
 */
export async function getGhidraMetadata(
  client: GhidraMcpClient,
): Promise<GhidraServerMetadata | null> {
  try {
    const result = await client.callTool("get_metadata", {})
    if (result.isError === true) {
      return null
    }
    const textBlock = result.content.find((b) => b.type === "text" && b.text != null)
    if (textBlock?.text == null) {
      return null
    }
    return JSON.parse(textBlock.text) as GhidraServerMetadata
  } catch {
    return null
  }
}

/**
 * List all tools exposed by the ghidra-mcp server.
 *
 * Delegates to {@link GhidraMcpClient.listTools}. Wraps errors into
 * {@link GhidraBridgeError}:
 * - `connection-closed` when the client is not connected
 * - `server-error` for any other failure
 *
 * The Orchestrator uses this to verify required tools are present before
 * launching the Reverser agent.
 *
 * @param client - A connected {@link GhidraMcpClient}.
 * @returns Array of {@link McpToolInfo} descriptors.
 * @throws {@link GhidraBridgeError} if the client is not connected or the
 *   server returns an error.
 */
export async function listGhidraTools(
  client: GhidraMcpClient,
): Promise<McpToolInfo[]> {
  if (!client.isConnected()) {
    throw new GhidraBridgeError({
      kind: "connection-closed",
      message:
        "Cannot list ghidra-mcp tools: client is not connected",
    })
  }
  try {
    return await client.listTools()
  } catch (err) {
    if (err instanceof GhidraBridgeError) {
      throw err
    }
    throw new GhidraBridgeError({
      kind: "server-error",
      message: `Failed to list ghidra-mcp tools: ${String(err)}`,
      serverError: String(err),
    })
  }
}

/**
 * Sensible default configuration for launching ghidra-mcp via stdio.
 *
 * Matches the bethington/ghidra-mcp launch convention: Python runs
 * `bridge_mcp_ghidra.py` from the working directory, with a generous
 * 60-second timeout to allow Ghidra analysis to complete on first run.
 *
 * @returns A ready-to-use {@link GhidraMcpConfig} for stdio transport.
 */
export function createDefaultGhidraConfig(): GhidraMcpConfig {
  return {
    type: "stdio",
    command: "python",
    args: ["bridge_mcp_ghidra.py"],
    timeoutMs: 60_000,
  }
}
