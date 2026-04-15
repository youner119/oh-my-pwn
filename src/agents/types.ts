import type { AgentConfig } from "@opencode-ai/sdk"

export type { AgentConfig }

/**
 * Agent mode determines UI model selection behavior:
 * - "primary": UI-selected model 따름
 * - "subagent": 자체 fallback chain, UI 선택 무시
 * - "all": 두 컨텍스트 모두 사용 가능
 */
export type AgentMode = "primary" | "subagent" | "all"

/**
 * Agent factory — (model: string) => AgentConfig, with static .mode property
 */
export type AgentFactory = ((model: string) => AgentConfig) & {
  mode: AgentMode
}
