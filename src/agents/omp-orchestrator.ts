import type { AgentConfig } from "./types"

/**
 * oh-my-pwn (OmP) Orchestrator agent — T01 scaffolding stub.
 *
 * At this milestone (M0/T01) the orchestrator is a no-op placeholder whose
 * only purpose is to prove out the OmP registration seam without disturbing
 * the existing workflow. Real orchestration (EnvSetup → Reverser →
 * VulnHunter → Exploiter ↔ Verifier → flag) lands in T18.
 *
 * Keep this file minimal: any logic heavier than "return an AgentConfig"
 * should live in sibling modules under src/agents/ so that the seam
 * edits to src/agents/{types,builtin-agents}.ts stay one-line.
 */

export const ompOrchestratorAgent: AgentConfig = {
  name: "omp-orchestrator",
  description:
    "oh-my-pwn orchestrator (T01 no-op placeholder). Future home of the CTF pwn auto-solve pipeline.",
  prompt:
    "You are the oh-my-pwn orchestrator placeholder. This agent is a scaffolding stub registered as part of T01. Reply with a short acknowledgement that the OmP registration seam is live, then stop.",
  model: "opus",
  defaultModel: "opus",
}

// ---------------------------------------------------------------------------
// Backward-compatibility factory (kept for src/index.ts re-export)
// ---------------------------------------------------------------------------

/** @deprecated Use ompOrchestratorAgent directly. */
export function createOmpOrchestratorAgent(_model: string): AgentConfig {
  return ompOrchestratorAgent
}
createOmpOrchestratorAgent.mode = "subagent" as const
