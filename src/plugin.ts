/**
 * oh-my-pwn (OmP) — opencode Plugin entry point.
 *
 * opencode의 config hook을 통해 omp agents를 Config.agent에 주입.
 * opencode TUI의 agent picker에서 선택 가능.
 *
 * MCP:
 *   - ghidra: bridge_mcp_ghidra.py (stdio) — reverser agent가 사용.
 *     브릿지 경로는 OMP_GHIDRA_BRIDGE_PATH 환경변수로만 지정 (하드코딩 없음).
 *     env var가 비어 있거나 파일이 존재하지 않으면 ghidra MCP 등록을 skip하고
 *     stderr에 경고를 남긴다. setup-omp.sh가 경로 탐지/alias 설정을 담당.
 *
 *   - pwno: pwno-mcp Docker (HTTP remote) — exploiter agent가 사용.
 *     http://127.0.0.1:5500/mcp 기본. OMP_PWNO_MCP_URL 환경변수로 override.
 *     Docker container가 실행 중이어야 동작. 없으면 skip + 경고.
 */

import { existsSync } from "node:fs"
import type { Plugin } from "@opencode-ai/plugin"
import { ompAgentConfigs } from "./agents/definitions"
import {
  ompReadStateTool,
  ompPatchStateTool,
  ompAppendJournalTool,
  ompRunEnvsetupTool,
  ompLoadChallengeTool,
  ompGetTemplateTool,
  ompVerifyTemplateOutputTool,
  ompSaveDecompiledTool,
} from "./tools"
import {
  BackgroundManager,
  PwnoContainerManager,
  createOmpTaskTool,
  createOmpTaskAllTool,
  createOmpTaskPoolTool,
  createOmpBackgroundOutputTool,
  createOmpPwnoContainerTool,
} from "./orchestration"
import type { OmpSessionClient } from "./orchestration"

const OmpPlugin: Plugin = async (input) => {
  // Capture SDK client for parallel orchestration infrastructure.
  // PluginInput.client is the OpencodeClient provided by opencode runtime.
  // We use client.session as our OmpSessionClient (subset of the SDK).
  // Cast through unknown because SDK generated types are more complex than
  // our minimal OmpSessionClient interface (union types, Request/Response wrappers).
  const pluginInput = input as unknown as {
    client?: { session: unknown }
    directory?: string
    serverUrl?: { toString(): string }
  }
  const sessionClient = pluginInput.client?.session as
    | OmpSessionClient
    | undefined
  const directory = pluginInput.directory ?? process.cwd()

  // Resolve the real server URL for tmux attach.
  // opencode starts with --port 0 (default), so the OS assigns an ephemeral port.
  // PluginInput.serverUrl may carry port 0 (pre-bind) — unusable for external attach.
  // Fallback: OPENCODE_PORT env var, or default 4096 (same pattern as OmO).
  const rawServerUrl = pluginInput.serverUrl?.toString()
  let serverUrl: string | undefined
  if (rawServerUrl) {
    try {
      const parsed = new URL(rawServerUrl)
      const port = parsed.port || (parsed.protocol === "https:" ? "443" : "80")
      if (port === "0") {
        const fallbackPort = process.env.OPENCODE_PORT ?? "4096"
        serverUrl = `http://localhost:${fallbackPort}`
      } else {
        serverUrl = rawServerUrl.replace(/\/+$/u, "")
      }
    } catch {
      serverUrl = rawServerUrl.replace(/\/+$/u, "")
    }
  }

  // Initialize BackgroundManager (parallel task lifecycle).
  // If no client available (e.g., test/debug), orchestration tools are still
  // registered but will fail with a clear error on invocation.
  if (serverUrl) {
    process.stderr.write(`[omp] serverUrl: ${serverUrl}\n`)
  } else {
    process.stderr.write(`[omp] WARNING: serverUrl not available — tmux panes will not work\n`)
  }

  const manager = sessionClient
    ? new BackgroundManager({ client: sessionClient, directory, serverUrl })
    : undefined

  const ompTaskTool = manager ? createOmpTaskTool(manager) : undefined
  const ompTaskAllTool = manager ? createOmpTaskAllTool(manager) : undefined
  const ompTaskPoolTool = manager ? createOmpTaskPoolTool(manager) : undefined
  const ompBackgroundOutputTool = manager
    ? createOmpBackgroundOutputTool(manager)
    : undefined

  // pwno-mcp container manager (single container, multi-session).
  const pwnoManager = new PwnoContainerManager()
  const ompPwnoContainerTool = createOmpPwnoContainerTool(pwnoManager)

  return {
    config: async (cfg) => {
      // ── agents ────────────────────────────────────────────────────────────
      cfg.agent ??= {}
      // omp 전용 환경에서 opencode 기본 agent 비활성화
      cfg.agent.build = { disable: true }
      cfg.agent.plan = { disable: true }
      Object.assign(cfg.agent, ompAgentConfigs)

      // ── mcp ───────────────────────────────────────────────────────────────
      // ghidra-mcp: bridge_mcp_ghidra.py를 stdio subprocess로 spawn.
      // Ghidra GUI를 열고 Tools > GhidraMCP > Start server (port 8089) 후 사용.
      // per-agent tool 제한은 T18 Orchestrator 구현 시 session.prompt tools 파라미터로 처리.
      const bridgePath = process.env["OMP_GHIDRA_BRIDGE_PATH"]
      if (bridgePath !== undefined && bridgePath !== "" && existsSync(bridgePath)) {
        cfg.mcp ??= {}
        ;(cfg.mcp as Record<string, unknown>)["ghidra"] = {
          type: "local",
          command: ["python3", bridgePath],
          enabled: true,
        }
      } else {
        const reason =
          bridgePath === undefined || bridgePath === ""
            ? "OMP_GHIDRA_BRIDGE_PATH is not set"
            : `OMP_GHIDRA_BRIDGE_PATH points to missing file: ${bridgePath}`
        process.stderr.write(
          `[omp] ghidra MCP not registered — ${reason}. ` +
            `Run ./scripts/setup-omp.sh (it auto-detects ~/Tools/ghidra_*_PUBLIC/bridge_mcp_ghidra.py, ` +
            `prompts if missing, and bakes the path into your omp alias).\n`,
        )
      }

      // pwno-mcp: Docker HTTP remote — exploiter agent의 gdb/pwndbg 관찰용.
      // docker run --rm -p 5500:5500 --cap-add=SYS_PTRACE --cap-add=SYS_ADMIN \
      //   --security-opt seccomp=unconfined -v "$PWD/workspace:/workspace" \
      //   ghcr.io/pwno-io/pwno-mcp:latest
      const pwnoUrl = process.env["OMP_PWNO_MCP_URL"] || "http://127.0.0.1:5500/mcp"
      const pwnoEnabled = process.env["OMP_PWNO_MCP_DISABLED"] !== "1"
      if (pwnoEnabled) {
        cfg.mcp ??= {}
        ;(cfg.mcp as Record<string, unknown>)["pwno"] = {
          type: "remote",
          url: pwnoUrl,
          enabled: true,
        }
      } else {
        process.stderr.write(
          `[omp] pwno MCP not registered — OMP_PWNO_MCP_DISABLED=1. ` +
            `Exploiter will not have gdb/memory inspection capabilities.\n`,
        )
      }
    },

    // ── tools ─────────────────────────────────────────────────────────────
    // state.json / journal.md 접근을 Zod-validated tool로 제공.
    // 에이전트는 이 tool을 통해서만 state를 읽고 씀 (직접 file write 금지).
    tool: {
      omp_load_challenge: ompLoadChallengeTool,
      omp_read_state: ompReadStateTool,
      omp_patch_state: ompPatchStateTool,
      omp_append_journal: ompAppendJournalTool,
      omp_run_envsetup: ompRunEnvsetupTool,
      omp_get_template: ompGetTemplateTool,
      omp_verify_template_output: ompVerifyTemplateOutputTool,
      omp_save_decompiled: ompSaveDecompiledTool,
      ...(ompTaskTool ? { omp_task: ompTaskTool } : {}),
      ...(ompTaskAllTool ? { omp_task_all: ompTaskAllTool } : {}),
      ...(ompTaskPoolTool ? { omp_task_pool: ompTaskPoolTool } : {}),
      ...(ompBackgroundOutputTool
        ? { omp_background_output: ompBackgroundOutputTool }
        : {}),
      omp_pwno_container: ompPwnoContainerTool,
    },
  }
}

export default OmpPlugin
