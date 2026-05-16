/**
 * omp_pwno_status — thin health check for the user-managed pwno-mcp container.
 *
 * OmP no longer manages the container lifecycle. The user starts the container
 * before running `omp`; this tool just verifies that:
 *   1. the container is reachable at the configured URL, and
 *   2. opencode has successfully connected to it as an MCP server.
 *
 * Orchestrator calls this at Phase 2 entry (and any time it wants a sanity
 * check) so failure is loud and the hint message points to the exact docker
 * command needed to start the container.
 */

import type { ToolDefinition } from "@opencode-ai/plugin/tool"
import { tool } from "@opencode-ai/plugin/tool"

export type ContainerProbe = (url: string) => Promise<boolean>

export interface PwnoStatusToolOptions {
  /** pwno-mcp endpoint (e.g. http://127.0.0.1:5500/mcp). */
  pwnoUrl: string
  /** opencode server URL, used to query MCP connection status. Optional. */
  serverUrl?: string
  /** Host workspace path the user is expected to mount (for the hint). */
  workspacePath: string
  /** TCP probe of the pwno-mcp endpoint. Defaults to a short fetch. */
  probe?: ContainerProbe
  /** Fetch implementation, injectable for tests. */
  fetchImpl?: typeof fetch
}

const DEFAULT_PROBE_TIMEOUT_MS = 2_000

async function defaultProbe(url: string): Promise<boolean> {
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), DEFAULT_PROBE_TIMEOUT_MS)
    try {
      // Any TCP-level response (even 4xx/5xx) means the container is up.
      // ECONNREFUSED / timeout / DNS failure → container down.
      await fetch(url, { method: "GET", signal: controller.signal })
      return true
    } finally {
      clearTimeout(timer)
    }
  } catch {
    return false
  }
}

function buildStartHint(pwnoUrl: string, workspacePath: string): string {
  const port = (() => {
    try {
      return new URL(pwnoUrl).port || "5500"
    } catch {
      return "5500"
    }
  })()
  return [
    `pwno-mcp container is not reachable at ${pwnoUrl}.`,
    `Start it with:`,
    `  docker run --rm -d --name omp-pwno \\`,
    `    -p ${port}:5500 \\`,
    `    --cap-add=SYS_PTRACE --cap-add=SYS_ADMIN \\`,
    `    --security-opt seccomp=unconfined \\`,
    `    -v "${workspacePath}:/workspace" \\`,
    `    ghcr.io/pwno-io/pwno-mcp:latest`,
  ].join("\n")
}

function buildReconnectHint(serverUrl: string | undefined, status: string): string {
  if (!serverUrl) {
    return `Container reachable but opencode reports pwno MCP status="${status}". Restart omp.`
  }
  return [
    `Container reachable but opencode reports pwno MCP status="${status}".`,
    `Try forcing a reconnect:`,
    `  curl -X POST ${serverUrl}/mcp/pwno/connect`,
    `or restart omp.`,
  ].join("\n")
}

export function createOmpPwnoStatusTool(
  options: PwnoStatusToolOptions,
): ToolDefinition {
  const probe = options.probe ?? defaultProbe
  const fetchImpl = options.fetchImpl ?? fetch

  return tool({
    description: `Verify that the pwno-mcp container is reachable and that opencode has connected to it.

OmP does NOT start the container — the user is expected to start it before running omp. Use this tool at Phase 2 entry (and any time you suspect a problem) to fail fast with a clear message.

Returns:
  {
    healthy: bool,                       // true only if container reachable AND mcp connected
    container_reachable: bool,
    container_url: string,
    mcp_status: "connected" | "failed" | "found" | "not_registered" | "unknown",
    hint?: string                        // present when NOT healthy — copy-pasteable fix
  }

If healthy=false, surface the hint to the user and STOP — do not proceed with exploitation.`,
    args: {},
    async execute() {
      const containerReachable = await probe(options.pwnoUrl)

      let mcpStatus: string = "unknown"
      if (options.serverUrl) {
        try {
          const res = await fetchImpl(`${options.serverUrl}/mcp`)
          if (res.ok) {
            const body = (await res.json().catch(() => null)) as
              | Record<string, { status?: string }>
              | null
            mcpStatus = body?.["pwno"]?.status ?? "not_registered"
          }
        } catch {
          // leave as "unknown"
        }
      }

      const healthy = containerReachable && mcpStatus === "connected"

      let hint: string | undefined
      if (!containerReachable) {
        hint = buildStartHint(options.pwnoUrl, options.workspacePath)
      } else if (mcpStatus !== "connected") {
        hint = buildReconnectHint(options.serverUrl, mcpStatus)
      }

      return JSON.stringify({
        healthy,
        container_reachable: containerReachable,
        container_url: options.pwnoUrl,
        mcp_status: mcpStatus,
        ...(hint ? { hint } : {}),
      })
    },
  })
}
