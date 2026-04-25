/**
 * Per-agent tool restrictions for OmP parallel pipeline.
 *
 * Merged into the `tools` object passed to session.promptAsync when
 * spawning a sub-agent session. `true` = allow, `false` = deny.
 *
 * Design:
 * - SA gets `omp_task: true` (needs to spawn Exploiter as sub-agent)
 * - Exploiter gets `omp_task: false` (no recursive spawning)
 * - VulnHunter gets `omp_task: false` (leaf agent)
 * - Reverser gets `omp_task: false` (leaf agent)
 */

const AGENT_RESTRICTIONS: Record<string, Record<string, boolean>> = {
  "omp-reverser": {
    omp_task: false,
    omp_background_output: false,
  },
  "omp-vulnhunter": {
    omp_task: false,
    omp_background_output: false,
  },
  "omp-strategist": {
    omp_task: true,
    omp_background_output: true,
  },
  "omp-exploiter": {
    omp_task: false,
    omp_background_output: false,
  },
}

/**
 * Get tool restriction map for an agent.
 * Returns `{}` for unknown agents (full access).
 */
export function getAgentToolRestrictions(
  agentName: string,
): Record<string, boolean> {
  return AGENT_RESTRICTIONS[agentName] ?? {}
}
