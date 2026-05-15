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
            // Runtime MCP registration + transport-level health verification +
            // tool-exposure verification.
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
            // Three-stage verification (each gates the next):
            //   1. mcp_registered: POST /mcp returns ok (opencode accepted config)
            //   2. mcp_connected:  POST /mcp/{name}/connect + GET /mcp polling
            //                      until status="connected" (transport open)
            //   3. mcp_tools_exposed: GET /experimental/tool/ids returns names
            //                        containing at least one `pwno_*` entry
            //                        (opencode actually enumerated MCP tools
            //                        into its tool registry — this is what
            //                        sub-agent sessions will see)
            //
            // mcp_tools_exposed is the strongest signal: if true, Exploiter
            // sub-agents will find pwno_list_debug_sessions / pwno_get_context /
            // etc. in their tool list. Orchestrator should not spawn SA until
            // mcp_tools_exposed: true.
            let mcpRegistered: boolean | undefined
            let mcpRegisterError: string | undefined
            let mcpConnected: boolean | undefined
            let mcpConnectError: string | undefined
            let mcpToolsExposed: boolean | undefined
            let mcpToolsError: string | undefined
            let pwnoToolSample: string[] | undefined
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

              // Stage 3: verify pwno_* tools actually appear in opencode's
              // tool registry. Transport=connected is necessary but not
              // sufficient — opencode might not have enumerated tools yet,
              // or the config-key→tool-prefix mapping might be wrong.
              if (mcpConnected) {
                try {
                  const toolRes = await fetch(`${serverUrl}/experimental/tool/ids`)
                  if (toolRes.ok) {
                    const ids = (await toolRes.json().catch(() => null)) as
                      | string[]
                      | null
                    if (Array.isArray(ids)) {
                      const pwnoIds = ids.filter((id) => id.startsWith("pwno_"))
                      if (pwnoIds.length > 0) {
                        mcpToolsExposed = true
                        pwnoToolSample = pwnoIds.slice(0, 6)
                      } else {
                        mcpToolsExposed = false
                        mcpToolsError = `no pwno_* tools in opencode registry (total ids: ${ids.length})`
                      }
                    } else {
                      mcpToolsExposed = false
                      mcpToolsError = "tool ids response was not an array"
                    }
                  } else {
                    mcpToolsExposed = false
                    mcpToolsError = `HTTP ${toolRes.status} from /experimental/tool/ids`
                  }
                } catch (err) {
                  mcpToolsExposed = false
                  mcpToolsError = String(err)
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
              ...(mcpToolsExposed !== undefined
                ? { mcp_tools_exposed: mcpToolsExposed }
                : {}),
              ...(mcpToolsError ? { mcp_tools_error: mcpToolsError } : {}),
              ...(pwnoToolSample ? { pwno_tool_sample: pwnoToolSample } : {}),
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
