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
import { createOmpExploiterMode0Agent } from "./omp-exploiter-mode-0"
import { createOmpExploiterMode9Agent } from "./omp-exploiter-mode-9"
import { createOmpSetupAgent } from "./omp-setup"

/** MVP default model. T18 model resolution layer 추가 시 교체. */
const DEFAULT_MODEL = "openai/gpt-5.5"

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
  "omp-orchestrator": createOmpOrchestratorAgent(DEFAULT_MODEL),
  "omp-setup": createOmpSetupAgent(DEFAULT_MODEL),
  "omp-reverser": createOmpReverserAgent(DEFAULT_MODEL),
  "omp-vulnhunter": createOmpVulnhunterAgent(DEFAULT_MODEL),
  "omp-strategist": createOmpStrategistAgent(DEFAULT_MODEL),
  "omp-exploiter-mode-1": createOmpExploiterMode1Agent(DEFAULT_MODEL),
  "omp-exploiter-mode-2": createOmpExploiterMode2Agent(DEFAULT_MODEL),
  "omp-exploiter-mode-0": createOmpExploiterMode0Agent(DEFAULT_MODEL),
  "omp-exploiter-mode-9": createOmpExploiterMode9Agent(DEFAULT_MODEL),
}
