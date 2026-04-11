/**
 * T06 — ghidra-mcp connection lifecycle manager.
 *
 * Manages the full lifecycle of a ghidra-mcp connection. Tries to attach to an
 * already-running Ghidra GUI first (SSE on port 8089); falls back to launching
 * `analyzeHeadless` and connecting via stdio when the GUI is unavailable.
 *
 * Usage:
 *
 *   const conn = await connectToGhidra({ binaryPath: "/tmp/chall" })
 *   console.log(conn.mode) // "gui" or "headless"
 *   await conn.ensureConnected()
 *   await conn.disconnect()
 */

import {
  buildHeadlessMcpConfig,
  runHeadlessImport,
  type HeadlessConfig,
  type HeadlessResult,
} from "./headless.js"
import { createGhidraMcpClient } from "./client.js"
import { checkGhidraHealth } from "./server.js"
import { GhidraBridgeError } from "./errors.js"
import type { GhidraMcpClient, GhidraMcpConfig } from "./types.js"

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Options for establishing a ghidra-mcp connection. */
export interface GhidraConnectionOptions {
  /** Binary path for headless import (needed for fallback). */
  binaryPath: string
  /** Port to try for GUI connection. Default: 8089. */
  guiPort?: number
  /** SSE URL for GUI. Default: `http://localhost:{guiPort}/sse`. */
  guiUrl?: string
  /** Timeout for GUI connection attempt in ms. Default: 5_000. */
  guiTimeoutMs?: number
  /** Headless config (ghidraHome, projectPath, etc.). */
  headlessConfig?: HeadlessConfig
  /** Factory for creating MCP clients (DI seam for tests). */
  createClient?: () => GhidraMcpClient
  /**
   * Override for `runHeadlessImport` — injected by tests to avoid real
   * filesystem and subprocess calls.
   */
  runHeadlessImport?: (
    binaryPath: string,
    config?: HeadlessConfig,
  ) => HeadlessResult
  /**
   * Override for `buildHeadlessMcpConfig` — injected by tests.
   */
  buildHeadlessMcpConfig?: (config?: HeadlessConfig) => GhidraMcpConfig
}

/** A live ghidra-mcp connection with lifecycle methods. */
export interface GhidraConnection {
  /** The connected client. */
  client: GhidraMcpClient
  /** How the connection was established. */
  mode: "gui" | "headless"
  /** Disconnect and clean up. */
  disconnect(): Promise<void>
  /** Check if still alive; reconnect using the original config if needed. */
  ensureConnected(): Promise<void>
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/**
 * Establish a ghidra-mcp connection.
 *
 * Step 1 — GUI probe: attempt an SSE connection to a running Ghidra GUI
 * (default port 8089) and verify health via `check_connection`.
 *
 * Step 2 — Headless fallback: run `analyzeHeadless` to import the binary,
 * then connect to `bridge_mcp_ghidra.py` via stdio.
 *
 * @param options - Connection options, including DI seams for testing.
 * @returns A connected {@link GhidraConnection}.
 * @throws {@link GhidraBridgeError} with kind `"connection-failed"` if both
 *   the GUI probe and the headless fallback fail.
 */
export async function connectToGhidra(
  options: GhidraConnectionOptions,
): Promise<GhidraConnection> {
  const {
    binaryPath,
    guiPort = 8089,
    guiTimeoutMs = 5_000,
    headlessConfig,
    createClient: clientFactory = createGhidraMcpClient,
    runHeadlessImport: doHeadlessImport = runHeadlessImport,
    buildHeadlessMcpConfig: doHeadlessConfig = buildHeadlessMcpConfig,
  } = options

  const guiUrl =
    options.guiUrl ?? `http://localhost:${guiPort}/sse`

  const guiConfig: GhidraMcpConfig = {
    type: "http",
    url: guiUrl,
    timeoutMs: guiTimeoutMs,
  }

  // Step 1: try GUI connection.
  const guiClient = clientFactory()
  let guiConnected = false
  try {
    await guiClient.connect(guiConfig)
    guiConnected = await checkGhidraHealth(guiClient)
  } catch {
    guiConnected = false
  }

  if (guiConnected) {
    return buildConnection(guiClient, "gui", guiConfig, clientFactory)
  }

  // Ensure the GUI client is cleaned up before headless fallback.
  try {
    await guiClient.disconnect()
  } catch {
    // Swallow — we're about to try a different transport anyway.
  }

  // Step 2: headless fallback.
  let headlessMcpConfig: GhidraMcpConfig
  try {
    doHeadlessImport(binaryPath, headlessConfig)
    headlessMcpConfig = doHeadlessConfig(headlessConfig)
  } catch (err) {
    throw new GhidraBridgeError({
      kind: "connection-failed",
      transport: "stdio",
      message: `Headless import failed: ${String(err)}`,
      code: (err as NodeJS.ErrnoException | undefined)?.code,
    })
  }

  const headlessClient = clientFactory()
  try {
    await headlessClient.connect(headlessMcpConfig)
  } catch (err) {
    throw new GhidraBridgeError({
      kind: "connection-failed",
      transport: "stdio",
      message: `Failed to connect to headless ghidra-mcp server: ${String(err)}`,
      code: (err as NodeJS.ErrnoException | undefined)?.code,
    })
  }

  return buildConnection(
    headlessClient,
    "headless",
    headlessMcpConfig,
    clientFactory,
  )
}

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

/**
 * Construct a {@link GhidraConnection} object wrapping the given client.
 *
 * Captures the config and client factory so `ensureConnected` can re-establish
 * the connection if it drops.
 */
function buildConnection(
  client: GhidraMcpClient,
  mode: "gui" | "headless",
  config: GhidraMcpConfig,
  clientFactory: () => GhidraMcpClient,
): GhidraConnection {
  // Track the active client in a mutable cell so ensureConnected can replace it.
  const state = { client }

  const connection: GhidraConnection = {
    get client(): GhidraMcpClient {
      return state.client
    },

    mode,

    async disconnect(): Promise<void> {
      await state.client.disconnect()
    },

    async ensureConnected(): Promise<void> {
      if (state.client.isConnected()) {
        return
      }
      // Replace with a fresh client and reconnect.
      const fresh = clientFactory()
      await fresh.connect(config)
      state.client = fresh
    },
  }

  return connection
}
