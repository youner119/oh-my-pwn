/**
 * omp_pwno_container — manage the single pwno-mcp Docker container.
 *
 * Orchestrator calls this to:
 * - ensure the container is running before spawning Exploiters
 * - allocate unique session_ids per candidate
 * - stop the container after pipeline completes
 */

import type { ToolDefinition } from "@opencode-ai/plugin/tool"
import { tool } from "@opencode-ai/plugin/tool"
import type { PwnoContainerManager } from "./container-manager"

export function createOmpPwnoContainerTool(
  manager: PwnoContainerManager,
  serverUrl?: string,
): ToolDefinition {
  return tool({
    description: `Manage the pwno-mcp Docker container for parallel Exploiter instances.

Actions:
- "ensure": Start the container if not running. Returns the MCP URL.
  pwno-mcp supports multiple debug sessions in one container via session_id.
- "allocate_session": Get a unique session_id for a candidate.
  Pass this session_id to the Exploiter so it uses its own isolated GDB session.
- "stop": Stop and remove the container after pipeline completes.
- "status": Check if the container is running.

Typical flow:
1. omp_pwno_container(action="ensure", workspace_path="/path/to/challenge/.omp")
2. omp_pwno_container(action="allocate_session", candidate_id="vuln_bof_main") → "exploit-vuln_bof_main"
3. ... spawn Exploiters with their session_ids ...
4. omp_pwno_container(action="stop")`,
    args: {
      action: tool.schema
        .string()
        .describe(
          'One of: "ensure", "allocate_session", "stop", "status".',
        ),
      workspace_path: tool.schema
        .string()
        .optional()
        .describe(
          'For "ensure": absolute path to mount as /workspace (typically <challenge-dir>/.omp).',
        ),
      candidate_id: tool.schema
        .string()
        .optional()
        .describe(
          'For "allocate_session": the candidate id to generate a session_id for.',
        ),
    },
    async execute(args: {
      action: string
      workspace_path?: string
      candidate_id?: string
    }) {
      try {
        switch (args.action) {
          case "ensure": {
            const status = await manager.ensure(args.workspace_path)
            // Runtime MCP registration + transport-level health verification.
            //
            // Background: opencode's plugin config hook fires at startup, before
            // the pwno container exists. opencode tries to connect once, fails
            // silently, and never retries. POST /mcp re-registers the config —
            // but opencode treats /mcp registration as lazy: it logs "found"
            // and only opens the transport on first tool use or session refresh.
            // Observed: a single POST /mcp left pwno in "found" state for 71min
            // until something else (a second ensure call) triggered the actual
            // transport=StreamableHTTP connected event.
            //
            // Two-stage verification:
            //   1. mcp_registered: POST /mcp returns ok (opencode accepted config)
            //   2. mcp_connected:  POST /mcp/{name}/connect + GET /mcp polling
            //                      until status="connected" (transport open)
            //
            // Why no tool-registry check: opencode does NOT include MCP-provided
            // tools in `/experimental/tool/ids` or `/experimental/tool` — both
            // endpoints return only built-in + plugin tools. MCP tools are
            // resolved per session.prompt at runtime. A `GET /experimental/
            // tool/ids` filter for `pwno_*` therefore always returns 0 even
            // when transport=connected and tools are usable inside sub-agent
            // sessions. (Verified 2026-05-15 against a live omp instance:
            // `/mcp` reported pwno+binja "connected", yet `/experimental/tool/ids`
            // contained zero `pwno_*` / `binja_*` entries — while VH sessions
            // simultaneously called `binja_get_data_decl` successfully.)
            //
            // Source of truth that pwno_* tools will be usable: `mcp_connected:
            // true` plus the binja precedent — both servers are registered the
            // same way (cfg.mcp[key] = {type:"remote"}), and binja already
            // works in production sessions exposed as `binja_<toolname>`.
            // opencode prefixes MCP tool names with `<configKey>_` at session
            // resolution time; for our cfg.mcp["pwno"] that yields `pwno_*`.
            let mcpRegistered: boolean | undefined
            let mcpRegisterError: string | undefined
            let mcpConnected: boolean | undefined
            let mcpConnectError: string | undefined
            if (serverUrl) {
              try {
                const res = await fetch(`${serverUrl}/mcp`, {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({
                    name: "pwno",
                    config: {
                      type: "remote",
                      url: status.url,
                      enabled: true,
                    },
                  }),
                })
                mcpRegistered = res.ok
                if (!res.ok) {
                  mcpRegisterError = `HTTP ${res.status}: ${await res.text().catch(() => "")}`
                }
              } catch (err) {
                mcpRegistered = false
                mcpRegisterError = String(err)
              }

              if (mcpRegistered) {
                // Force transport open. /mcp/{name}/connect may itself return
                // a status block; we ignore the body and rely on the polling
                // loop below for the source of truth.
                try {
                  await fetch(`${serverUrl}/mcp/pwno/connect`, { method: "POST" })
                } catch {
                  // Non-fatal: opencode may auto-connect on the first GET /mcp.
                }

                const CONNECT_TIMEOUT_MS = 30_000
                const POLL_INTERVAL_MS = 500
                const deadline = Date.now() + CONNECT_TIMEOUT_MS
                while (Date.now() < deadline) {
                  let statusOk = false
                  try {
                    const statusRes = await fetch(`${serverUrl}/mcp`)
                    if (statusRes.ok) {
                      const body = (await statusRes.json().catch(() => null)) as
                        | Record<string, { status: string; error?: string }>
                        | null
                      const pwno = body?.["pwno"]
                      if (pwno?.status === "connected") {
                        mcpConnected = true
                        statusOk = true
                        break
                      }
                      if (pwno?.status === "failed") {
                        mcpConnected = false
                        mcpConnectError = pwno.error || "pwno MCP status=failed"
                        statusOk = true
                        break
                      }
                      // "needs_auth" / "needs_client_registration" / undefined →
                      // keep polling; opencode may still be establishing.
                    }
                  } catch (err) {
                    mcpConnectError = String(err)
                  }
                  if (statusOk) break
                  await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS))
                }
                if (mcpConnected === undefined) {
                  mcpConnected = false
                  mcpConnectError =
                    mcpConnectError ??
                    `timeout (${CONNECT_TIMEOUT_MS}ms) waiting for pwno transport=connected`
                }
              }
            }
            return JSON.stringify({
              ok: true,
              action: "ensure",
              ...status,
              ...(mcpRegistered !== undefined
                ? { mcp_registered: mcpRegistered }
                : {}),
              ...(mcpRegisterError ? { mcp_register_error: mcpRegisterError } : {}),
              ...(mcpConnected !== undefined
                ? { mcp_connected: mcpConnected }
                : {}),
              ...(mcpConnectError ? { mcp_connect_error: mcpConnectError } : {}),
            })
          }
          case "allocate_session": {
            if (!args.candidate_id) {
              return JSON.stringify({
                error: "missing_candidate_id",
                message: "candidate_id is required for allocate_session",
              })
            }
            const sessionId = manager.allocateSessionId(args.candidate_id)
            return JSON.stringify({
              ok: true,
              action: "allocate_session",
              session_id: sessionId,
              candidate_id: args.candidate_id,
            })
          }
          case "stop": {
            await manager.stop()
            return JSON.stringify({ ok: true, action: "stop" })
          }
          case "status": {
            const running = await manager.isRunning()
            return JSON.stringify({
              ok: true,
              action: "status",
              running,
              url: manager.url,
            })
          }
          default:
            return JSON.stringify({
              error: "unknown_action",
              message: `Unknown action: ${args.action}. Use "ensure", "allocate_session", "stop", or "status".`,
            })
        }
      } catch (err) {
        return JSON.stringify({
          error: "container_error",
          message: String(err),
        })
      }
    },
  })
}
