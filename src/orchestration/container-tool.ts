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
            // Runtime MCP registration: opencode's plugin config hook fires at
            // startup, before the pwno container exists. opencode tries to
            // connect once, fails silently, and never retries. So we re-register
            // here via the /mcp POST endpoint now that the server is live.
            // Without this step, exploiter sub-agents see zero pwno-mcp tools.
            let mcpRegistered: boolean | undefined
            let mcpRegisterError: string | undefined
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
            }
            return JSON.stringify({
              ok: true,
              action: "ensure",
              ...status,
              ...(mcpRegistered !== undefined
                ? { mcp_registered: mcpRegistered }
                : {}),
              ...(mcpRegisterError ? { mcp_register_error: mcpRegisterError } : {}),
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
