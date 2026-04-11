/**
 * OmP agent definitions registry.
 *
 * Maps all OmP agents to the oh-my-claudecode AgentConfig shape so they can
 * be registered with the Claude Agent SDK agent registry.
 */

import type { AgentConfig } from "./types"
import { ompOrchestratorAgent } from "./omp-orchestrator"
import { ompReverserAgent } from "./omp-reverser"

/**
 * Returns all OmP agent definitions keyed by agent name.
 *
 * The returned shape matches the subset expected by the Claude Agent SDK
 * (description, prompt, model — tools/disallowedTools are optional and
 * omitted here until downstream agents require them).
 */
export function getOmpAgentDefinitions(): Record<
  string,
  { description: string; prompt: string; model?: string }
> {
  const agents: AgentConfig[] = [ompOrchestratorAgent, ompReverserAgent]

  const result: Record<string, { description: string; prompt: string; model?: string }> = {}
  for (const agent of agents) {
    result[agent.name] = {
      description: agent.description,
      prompt: agent.prompt,
      model: agent.model,
    }
  }
  return result
}
