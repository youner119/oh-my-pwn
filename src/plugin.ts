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
 *     않음. 컨테이너 가용성 sanity-check + 챌린지 파일 staging 은 모두
 *     omp-setup agent (Phase 5) 가 단일 transaction 으로 처리.
 *     컨테이너 mount source 는 repo root 의 workspace/ (고정).
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
  createOmpLoadChallengeTool,
  ompGetTemplateTool,
  ompVerifyTemplateOutputTool,
  createOmpSetupDockerBuildTool,
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

  // Initialize BackgroundManager (parallel task lifecycle).
  // If no client available (e.g., test/debug), orchestration tools are still
  // registered but will fail with a clear error on invocation.
  const manager = sessionClient
    ? new BackgroundManager({
        client: sessionClient,
        directory,
        enableEventLog: true,
      })
    : undefined

  const ompTaskLaunchTool = manager ? createOmpTaskLaunchTool(manager) : undefined
  const ompTaskWaitAllTool = manager ? createOmpTaskWaitAllTool(manager) : undefined
  const ompTaskWaitAnyTool = manager ? createOmpTaskWaitAnyTool(manager) : undefined
  const ompTaskCancelTool = manager ? createOmpTaskCancelTool(manager) : undefined

  // omp_load_challenge — factory so we can wire OMP_WORKSPACE_PATH into
  // state.workspace_root (T01.6). Downstream agents read this for
  // deterministic per-challenge workspace path derivation.
  const ompLoadChallengeTool = createOmpLoadChallengeTool({
    workspacePath: OMP_WORKSPACE_PATH,
    onLoaded: manager
      ? ({ sessionID, agent, challengeName }) => {
          manager.registerOrchestrator(sessionID, agent, challengeName)
        }
      : undefined,
  })

  // pwno-mcp HTTP MCP URL — wired below as an MCP remote for sub-agent
  // sessions so Exploiter can call `pwno_*` tools. The legacy
  // omp_pwno_status health-check tool was retired by T14; sanity-check
  // moved into the omp-setup agent (Phase 5 bash: docker ps + curl).
  const pwnoUrl = process.env["OMP_PWNO_MCP_URL"] || "http://127.0.0.1:5500/mcp"

  // omp-setup agent atomic tool surface (Phase B fully implemented in
  // T04/T06/T07/T08). Spec: `.omc/specs/deep-interview-envsetup-agent.md`.
  // inspect_folder / probe_image were considered then deferred — Phase 0 is
  // fully agentic (bash inspection), so deterministic tools for those are
  // not needed.
  //
  // omp_run_envsetup / omp_stage_challenge / omp_pwno_status were retired
  // by T12-T14 — omp-setup agent absorbs all three (build via
  // omp_setup_docker_build, stage via omp_setup_extract_file host-mode,
  // pwno sanity via bash docker ps + curl).
  const ompSetupDockerBuildTool = createOmpSetupDockerBuildTool()
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
      omp_get_template: ompGetTemplateTool,
      omp_verify_template_output: ompVerifyTemplateOutputTool,
      // omp_save_decompiled removed — use BN MCP tool `decompile_to_file` instead.
      // omp_run_envsetup / omp_stage_challenge / omp_pwno_status retired by
      // T12-T14 — omp-setup agent absorbs all three.
      // 4-tool sub-agent surface — fire-and-forget + explicit wait/cancel.
      ...(ompTaskLaunchTool ? { omp_task_launch: ompTaskLaunchTool } : {}),
      ...(ompTaskWaitAllTool ? { omp_task_wait_all: ompTaskWaitAllTool } : {}),
      ...(ompTaskWaitAnyTool ? { omp_task_wait_any: ompTaskWaitAnyTool } : {}),
      ...(ompTaskCancelTool ? { omp_task_cancel: ompTaskCancelTool } : {}),
      // omp-setup agent atomic tools (Phase B — T04/T06/T07/T08).
      // inspect_folder / probe_image deferred — Phase 0 is fully agentic.
      omp_setup_docker_build: ompSetupDockerBuildTool,
      omp_setup_extract_file: ompSetupExtractFileTool,
      omp_setup_patch_elf: ompSetupPatchElfTool,
      omp_setup_verify_runtime: ompSetupVerifyRuntimeTool,
    },
  }
}

export default OmpPlugin
