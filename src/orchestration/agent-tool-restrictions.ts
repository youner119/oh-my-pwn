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

/**
 * State write tools — Orchestrator sole writer per
 * `.omc/specs/state-split-vuln-candidates.md` D6 + the original
 * parallel-orchestration spec. Sub-agents return changes in their task
 * result; the Orchestrator persists via these tools. `omp_read_*` and
 * `omp_append_journal` stay allowed (read + journal append).
 */
const STATE_WRITE_DENY = {
  omp_patch_state: false,
  omp_create_candidate: false,
  omp_patch_candidate: false,
  omp_delete_candidate: false,
} as const

const AGENT_RESTRICTIONS: Record<string, Record<string, boolean>> = {
  "omp-setup": {
    // Leaf agent — single-transaction Phase 0 ground-work. No
    // child spawning.
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
    ...STATE_WRITE_DENY,
  },
  "omp-reverser": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
    ...STATE_WRITE_DENY,
  },
  "omp-vulnhunter": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
    ...STATE_WRITE_DENY,
  },
  "omp-strategist": {
    omp_task_launch: true,
    omp_task_wait_all: true,
    omp_task_wait_any: true,
    omp_task_cancel: true,
    ...STATE_WRITE_DENY,
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
    ...STATE_WRITE_DENY,
  },
  "omp-exploiter-mode-2": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
    ...STATE_WRITE_DENY,
  },
  "omp-exploiter-mode-0": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
    ...STATE_WRITE_DENY,
  },
  "omp-exploiter-mode-9": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
    ...STATE_WRITE_DENY,
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
