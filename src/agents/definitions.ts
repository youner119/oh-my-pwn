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
import { createOmpExploiterAgent } from "./omp-exploiter"

/** MVP default model. T18 model resolution layer 추가 시 교체. */
const DEFAULT_MODEL = "openai/gpt-5.4"

/**
 * agent name → AgentConfig 매핑.
 * plugin.ts의 config hook에서 opencode Config.agent에 주입.
 */
export const ompAgentConfigs: Record<string, AgentConfig> = {
  "omp-orchestrator": createOmpOrchestratorAgent(DEFAULT_MODEL),
  "omp-reverser": createOmpReverserAgent(DEFAULT_MODEL),
  "omp-vulnhunter": createOmpVulnhunterAgent(DEFAULT_MODEL),
  "omp-strategist": createOmpStrategistAgent(DEFAULT_MODEL),
  "omp-exploiter": createOmpExploiterAgent(DEFAULT_MODEL),
}
