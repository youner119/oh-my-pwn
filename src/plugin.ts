/**
 * oh-my-pwn (OmP) — opencode Plugin entry point.
 *
 * opencode의 config hook을 통해 omp-orchestrator, omp-reverser를
 * Config.agent에 주입. opencode TUI의 agent picker에서 선택 가능.
 *
 * MCP:
 *   - ghidra: bridge_mcp_ghidra.py (stdio) — reverser agent가 사용.
 *     브릿지 경로는 OMP_GHIDRA_BRIDGE_PATH 환경변수로만 지정 (하드코딩 없음).
 *     env var가 비어 있거나 파일이 존재하지 않으면 ghidra MCP 등록을 skip하고
 *     stderr에 경고를 남긴다. setup-omp.sh가 경로 탐지/alias 설정을 담당.
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
} from "./tools"

const OmpPlugin: Plugin = async (_input) => {
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
    },
  }
}

export default OmpPlugin
