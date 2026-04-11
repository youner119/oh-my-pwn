/**
 * OmP agent types — aligned with oh-my-claudecode AgentConfig pattern.
 */

export interface AgentConfig {
  name: string
  description: string
  prompt: string
  model?: string
  defaultModel?: string
  tools?: string[]
  disallowedTools?: string[]
}

// ---------------------------------------------------------------------------
// Backward-compatibility aliases (kept for src/index.ts re-exports)
// ---------------------------------------------------------------------------

/** @deprecated Not used in the new AgentConfig shape. */
export type AgentMode = "primary" | "subagent" | "all"

/** @deprecated Factory pattern replaced by exported AgentConfig constants. */
export type AgentFactory = {
  (model: string): AgentConfig
  mode: AgentMode
}
