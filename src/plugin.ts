/**
 * oh-my-pwn (OmP) — opencode Plugin entry point.
 *
 * opencode의 config hook을 통해 omp agents를 Config.agent에 주입.
 * opencode TUI의 agent picker에서 선택 가능.
 *
 * MCP:
 *   - binja: Binary Ninja MCP bridge (Node stdio) — reverser agent가 사용.
 *     OMP_BN_BRIDGE_PATH 환경변수로 bridge dist 경로 지정.
 *
 *   - pwno: pwno-mcp Docker (HTTP remote) — exploiter agent가 사용.
 *     http://127.0.0.1:5500/mcp 기본, OMP_PWNO_MCP_URL로 override.
 *     **컨테이너는 사용자가 omp 실행 전에 직접 띄움.** OmP는 lifecycle 관리하지
 *     않음. omp_pwno_status tool로 컨테이너/MCP 연결 상태만 sanity check.
 *     컨테이너 mount source는 repo root의 workspace/ (고정) — omp_stage_challenge가
 *     challenge 파일을 여기로 복사한다.
 */

import { existsSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import type { Plugin } from "@opencode-ai/plugin"
import { ompAgentConfigs } from "./agents/definitions"
import {
  installAgentSortShim,
  reorderAgentsByPriority,
} from "./agents/agent-sort-shim"
import {
  ompReadStateTool,
  ompPatchStateTool,
  ompAppendJournalTool,
  ompRunEnvsetupTool,
  ompLoadChallengeTool,
  ompGetTemplateTool,
  ompVerifyTemplateOutputTool,
  createOmpStageChallengeTool,
  createOmpSetupInspectFolderTool,
  createOmpSetupDockerBuildTool,
  createOmpSetupProbeImageTool,
  createOmpSetupExtractFileTool,
  createOmpSetupPatchElfTool,
  createOmpSetupVerifyRuntimeTool,
} from "./tools"
import {
  BackgroundManager,
  createOmpTaskLaunchTool,
  createOmpTaskWaitAllTool,
  createOmpTaskWaitAnyTool,
  createOmpTaskCancelTool,
  createOmpPwnoStatusTool,
} from "./orchestration"
import type { OmpSessionClient } from "./orchestration"

/** Repo root (parent of dist/plugin.js). Used as the canonical workspace mount source. */
const OMP_REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const OMP_WORKSPACE_PATH = resolve(OMP_REPO_ROOT, "workspace")

// Install at module load so the patch is in place before opencode's agent
// list sort runs (Remeda sortBy in packages/opencode/src/agent/agent.ts).
// Idempotent.
installAgentSortShim()

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

  const ompTaskLaunchTool = manager ? createOmpTaskLaunchTool(manager) : undefined
  const ompTaskWaitAllTool = manager ? createOmpTaskWaitAllTool(manager) : undefined
  const ompTaskWaitAnyTool = manager ? createOmpTaskWaitAnyTool(manager) : undefined
  const ompTaskCancelTool = manager ? createOmpTaskCancelTool(manager) : undefined

  // pwno-mcp health check tool. Container lifecycle is the user's
  // responsibility — they start it before omp. This tool just probes the
  // configured URL and reports opencode's MCP connection status so the
  // Orchestrator can fail fast at Phase 2 entry.
  const pwnoUrl = process.env["OMP_PWNO_MCP_URL"] || "http://127.0.0.1:5500/mcp"
  const ompPwnoStatusTool = createOmpPwnoStatusTool({
    pwnoUrl,
    serverUrl,
    workspacePath: OMP_WORKSPACE_PATH,
  })

  // Stage challenge files into the canonical workspace mount source.
  // Orchestrator calls this once at Phase 2 entry, then forwards the returned
  // container_path values to StrategyAgent.
  const ompStageChallengeTool = createOmpStageChallengeTool({
    workspacePath: OMP_WORKSPACE_PATH,
  })

  // omp-setup agent atomic tool surface (T02 skeletons; T03–T08 implementations).
  // Spec: `.omc/specs/deep-interview-envsetup-agent.md`. Tools currently return
  // not_implemented stubs — full bodies land in T03–T08. Registered now so the
  // surface is stable when the omp-setup agent (T09) and Orchestrator Phase 0
  // rewrite (T11) consume it.
  const ompSetupInspectFolderTool = createOmpSetupInspectFolderTool()
  const ompSetupDockerBuildTool = createOmpSetupDockerBuildTool()
  const ompSetupProbeImageTool = createOmpSetupProbeImageTool()
  const ompSetupExtractFileTool = createOmpSetupExtractFileTool()
  const ompSetupPatchElfTool = createOmpSetupPatchElfTool()
  const ompSetupVerifyRuntimeTool = createOmpSetupVerifyRuntimeTool()

  return {
    config: async (cfg) => {
      // ── agents ────────────────────────────────────────────────────────────
      cfg.agent ??= {}
      // omp 전용 환경에서 opencode 기본 agent 비활성화
      cfg.agent.build = { disable: true }
      cfg.agent.plan = { disable: true }
      Object.assign(cfg.agent, ompAgentConfigs)

      // Force omp-orchestrator first in the TUI picker. opencode 1.4.x
      // alphabetizes by agent name (sst/opencode#19127) which puts
      // omp-exploiter first. reorderAgentsByPriority restores the
      // OMP_AGENT_ORDER and injects `order: N` for future-proofing; the
      // Array.prototype shim installed at module load enforces it against
      // opencode's runtime sort.
      cfg.agent = reorderAgentsByPriority(cfg.agent)

      // ── mcp ───────────────────────────────────────────────────────────────
      // binary-ninja-mcp: bridge (Node.js stdio) → BN plugin HTTP (port 9009).
      // BN GUI를 열면 MCP plugin이 자동 시작. POST /load로 바이너리 로드.
      // per-agent tool 제한은 T18 Orchestrator 구현 시 session.prompt tools 파라미터로 처리.
      const bnBridgePath = process.env["OMP_BN_BRIDGE_PATH"]
      const bnPort = process.env["OMP_BN_PORT"] || "9009"
      if (bnBridgePath !== undefined && bnBridgePath !== "" && existsSync(bnBridgePath)) {
        cfg.mcp ??= {}
        ;(cfg.mcp as Record<string, unknown>)["binja"] = {
          type: "local",
          command: ["node", bnBridgePath, "--host", "localhost", "--port", bnPort],
          enabled: true,
        }
      } else {
        const reason =
          bnBridgePath === undefined || bnBridgePath === ""
            ? "OMP_BN_BRIDGE_PATH is not set"
            : `OMP_BN_BRIDGE_PATH points to missing file: ${bnBridgePath}`
        process.stderr.write(
          `[omp] binja MCP not registered — ${reason}. ` +
            `Set OMP_BN_BRIDGE_PATH to ~/Tools/binary_ninja_mcp/bridge/dist/index.js\n`,
        )
      }

      // pwno-mcp: HTTP remote MCP — exploiter agent의 gdb/pwndbg 관찰용.
      // 컨테이너는 사용자가 직접 띄움 — repo root의 workspace/를 mount하면 된다:
      //   docker run --rm -d --name omp-pwno -p 5500:5500 \
      //     --cap-add=SYS_PTRACE --cap-add=SYS_ADMIN \
      //     --security-opt seccomp=unconfined \
      //     -v "${OMP_WORKSPACE_PATH}:/workspace" \
      //     ghcr.io/pwno-io/pwno-mcp:latest
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
      // omp_save_decompiled removed — use BN MCP tool `decompile_to_file` instead.
      // 4-tool sub-agent surface — fire-and-forget + explicit wait/cancel.
      ...(ompTaskLaunchTool ? { omp_task_launch: ompTaskLaunchTool } : {}),
      ...(ompTaskWaitAllTool ? { omp_task_wait_all: ompTaskWaitAllTool } : {}),
      ...(ompTaskWaitAnyTool ? { omp_task_wait_any: ompTaskWaitAnyTool } : {}),
      ...(ompTaskCancelTool ? { omp_task_cancel: ompTaskCancelTool } : {}),
      omp_pwno_status: ompPwnoStatusTool,
      omp_stage_challenge: ompStageChallengeTool,
      // omp-setup agent atomic tools (T02 skeletons).
      omp_setup_inspect_folder: ompSetupInspectFolderTool,
      omp_setup_docker_build: ompSetupDockerBuildTool,
      omp_setup_probe_image: ompSetupProbeImageTool,
      omp_setup_extract_file: ompSetupExtractFileTool,
      omp_setup_patch_elf: ompSetupPatchElfTool,
      omp_setup_verify_runtime: ompSetupVerifyRuntimeTool,
    },
  }
}

export default OmpPlugin
