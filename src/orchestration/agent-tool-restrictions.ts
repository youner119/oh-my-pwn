/**
 * Per-agent tool restrictions for OmP parallel pipeline.
 *
 * Merged into the `tools` object passed to session.promptAsync when
 * spawning a sub-agent session. `true` = allow, `false` = deny.
 *
 * Design (post-T9 cutover, 4-tool surface):
 * - SA spawns Exploiter → needs the full launch/wait/cancel surface
 * - Exploiter, VulnHunter, Reverser are leaf agents — no child spawning
 *
 * The four orchestration tools come as a coherent set; we toggle them
 * together so an agent can't half-spawn (launch without wait, etc.).
 */

const AGENT_RESTRICTIONS: Record<string, Record<string, boolean>> = {
  "omp-setup": {
    // Leaf agent — single-transaction Phase 0 ground-work. No
    // child spawning.
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
  },
  "omp-reverser": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
  },
  "omp-vulnhunter": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
  },
  "omp-strategist": {
    omp_task_launch: true,
    omp_task_wait_all: true,
    omp_task_wait_any: true,
    omp_task_cancel: true,
  },
  // Exploiter — 4 mode agents (post `mode-0-9-setup` T8 cutover). All
  // four are leaf agents with the same restriction shape (cannot spawn
  // sub-agents). Listed individually so unknown-agent fallback (`{}` =
  // full access) does not accidentally relax any of them.
  "omp-exploiter-mode-1": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
  },
  "omp-exploiter-mode-2": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
  },
  "omp-exploiter-mode-0": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
  },
  "omp-exploiter-mode-9": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
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
