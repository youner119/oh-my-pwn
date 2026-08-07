/**
 * OmP agent sources registry.
 *
 * MVP: factory를 하드코딩된 기본 모델로 호출.
 * T18에서 model resolution layer 추가 시 factories를 직접 노출.
 */

import type { AgentConfig } from "./types"
import { createOmpOrchestratorAgent } from "./omp-orchestrator"
import { createOmpReverserAgent } from "./omp-reverser"
import { createOmpVulnhunterAgent } from "./omp-vulnhunter"
import { createOmpStrategistAgent } from "./omp-strategist"
import { createOmpExploiterMode1Agent } from "./omp-exploiter-mode-1"
import { createOmpExploiterMode2Agent } from "./omp-exploiter-mode-2"
import { createOmpExploiterMode1GptAgent } from "./omp-exploiter-mode-1-gpt"
import { createOmpExploiterMode2GptAgent } from "./omp-exploiter-mode-2-gpt"
import { createOmpExploiterMode0Agent } from "./omp-exploiter-mode-0"
import { createOmpExploiterMode9Agent } from "./omp-exploiter-mode-9"
import { createOmpSetupAgent } from "./omp-setup"

/**
 * Per-agent default models — Axis A of the model-routing policy
 * (`.omc/decisions.md` #5, user policy 2026-06-12). Each agent is registered
 * with the model that fits its role by default; the launch-time `model` arg
 * (commit a4661ad) overrides per spawn whenever the user specifies otherwise.
 *
 *   orchestrator / reverser / strategist → Claude  (coordination, deep
 *       reasoning, adversarial verify)
 *   setup / exploiter                    → GPT      (mechanical env work,
 *       terminal/iterative execution)
 *   vulnhunter                           → Claude registration default, but
 *       the ensemble runs half-half Claude:GPT (Claude +1 on odd N) — the
 *       Orchestrator assigns GPT to floor(N/2) members at spawn via the model
 *       arg (N=5 → 3 Claude, 2 GPT).
 */
const CLAUDE_MODEL = "anthropic/claude-opus-4-8"
const GPT_MODEL = "openai/gpt-5.6-sol"

/**
 * agent name → AgentConfig 매핑.
 * plugin.ts의 config hook에서 opencode Config.agent에 주입.
 *
 * Exploiter는 4 mode agent로 분리 등록 (spec
 * `.omc/specs/deep-interview-mode-0-9-setup.md` T8 cutover). 단일
 * `omp-exploiter` 폐기. Orchestrator가 SA의 `recommended_mode` 또는
 * `mode_override`를 보고 spawn 시점에 mode 별 agent name으로 분기.
 *
 * - `omp-exploiter-mode-1` — host pwntools, stdout-only evidence
 * - `omp-exploiter-mode-2` — pwno-mcp driver + explicit GDB attach
 * - `omp-exploiter-mode-0` — autonomous fallback (unsupported challenge_type)
 * - `omp-exploiter-mode-9` — user-supplied prompt forwarded by the user
 */
export const ompAgentConfigs: Record<string, AgentConfig> = {
  "omp-orchestrator": createOmpOrchestratorAgent(CLAUDE_MODEL),
  "omp-setup": createOmpSetupAgent(GPT_MODEL),
  "omp-reverser": createOmpReverserAgent(CLAUDE_MODEL),
  "omp-vulnhunter": createOmpVulnhunterAgent(CLAUDE_MODEL),
  "omp-strategist": createOmpStrategistAgent(CLAUDE_MODEL),
  "omp-exploiter-mode-1": createOmpExploiterMode1Agent(GPT_MODEL),
  "omp-exploiter-mode-2": createOmpExploiterMode2Agent(GPT_MODEL),
  "omp-exploiter-mode-0": createOmpExploiterMode0Agent(GPT_MODEL),
  "omp-exploiter-mode-9": createOmpExploiterMode9Agent(GPT_MODEL),
  // GPT/principle-driven prompt variants — opt-in (user-specified). Same GPT
  // default model. Decision: `.omc/decisions.md` #5.
  "omp-exploiter-mode-1-gpt": createOmpExploiterMode1GptAgent(GPT_MODEL),
  "omp-exploiter-mode-2-gpt": createOmpExploiterMode2GptAgent(GPT_MODEL),
}
