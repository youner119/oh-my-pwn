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
 *   - pwno-mcp: opencode-managed stdio docker (image `pwno-mcp:latest`, fork
 *     local build from ~/Tools/pwno-mcp). opencode.json 의 mcp 정적 entry 로
 *     자동 spawn — setup-omp.sh 가 그 entry 를 박는다. Plugin code 가 MCP
 *     주입하지 않음.
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
    // chat.params — reasoning effort injection (P2 of variant-via-plugin).
    // env `OMP_REASONING_EFFORT` (e.g. "xhigh" / "high" / "medium") gates this;
    // unset → no-op (safe default). Applied only to OpenAI calls from OmP agents
    // (`omp-*`) so user-added agents or Anthropic providers stay untouched.
    //
    // The exact key opencode forwards to the SDK is undocumented for the
    // `--variant` flag, so we set both Vercel AI SDK's
    // `providerOptions.openai.reasoningEffort` and a top-level
    // `reasoningEffort` fallback. Unrecognized keys are ignored by the
    // downstream provider.
    "chat.params": async (input, output) => {
      const effort = process.env["OMP_REASONING_EFFORT"]
      if (!effort) return
      if (input.provider.info.id !== "openai") return
      if (!input.agent.startsWith("omp-")) return

      const providerOpts =
        (output.options["providerOptions"] as Record<string, unknown> | undefined) ?? {}
      const openaiOpts =
        (providerOpts["openai"] as Record<string, unknown> | undefined) ?? {}
      output.options["providerOptions"] = {
        ...providerOpts,
        openai: { ...openaiOpts, reasoningEffort: effort },
      }
      output.options["reasoningEffort"] = effort
    },

    config: async (cfg) => {
      // ── agents ────────────────────────────────────────────────────────────
      cfg.agent ??= {}
      // omp 전용 환경에서 opencode 기본 agent 비활성화
      cfg.agent.build = { disable: true }
      cfg.agent.plan = { disable: true }
      Object.assign(cfg.agent, ompAgentConfigs)

      // Force omp-orchestrator first in the TUI picker. opencode 1.4.x
      // alphabetizes by agent name (sst/opencode#19127) which puts
      // omp-exploiter-mode-0 first (after the T8 cutover to mode-suffixed
      // exploiter agents). reorderAgentsByPriority restores the
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

      // pwno-mcp: registered statically in opencode.json (mcp.pwno-mcp,
      // stdio). setup-omp.sh writes that entry from a fixed template — see
      // scripts/setup-omp.sh. Plugin code does not inject the pwno MCP.
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
