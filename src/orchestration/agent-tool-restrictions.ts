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
 * DB write tools — ACL Layer 1 (spec: deep-interview-database-mcp.md, AC4,
 * 2026-06-05 정정). State/candidate access moved to the omp-db MCP server
 * (`mcp__omp-db__*`); the file-era `omp_*` plugin tools were removed in T8.
 *
 * The write surface is per-channel, not a blanket sole-writer:
 *
 * - `patch_state` (state) has THREE writers — orchestrator + setup(Phase 0
 *   detect/env) + reverser(its own artifacts metadata). So the setup/reverser
 *   deny set keeps `patch_state` ALLOWED and denies only candidate/challenge
 *   writes.
 * - candidate writes (`create/patch/delete_candidate`) + challenge writes
 *   (`register/update_challenge`) are orchestrator-only.
 * - VH / SA / Exploiter are read-only → deny ALL DB writes.
 *
 * Reads (`read_state` / `read_candidate` / `read_challenge`) stay allowed for
 * everyone. Layer 2 (server-side `agent_id` allowlist) is the real enforcement;
 * this layer just minimises surface exposure.
 */
const DB_WRITE_DENY_CANDIDATE_CHALLENGE = {
  "mcp__omp-db__create_candidate": false,
  "mcp__omp-db__patch_candidate": false,
  "mcp__omp-db__delete_candidate": false,
  "mcp__omp-db__register_challenge": false,
  "mcp__omp-db__update_challenge": false,
  "mcp__omp-db__delete_challenge": false,
  // patch_state intentionally NOT denied — setup / reverser are state writers.
} as const

const DB_WRITE_DENY_ALL = {
  "mcp__omp-db__patch_state": false,
  ...DB_WRITE_DENY_CANDIDATE_CHALLENGE,
} as const

/**
 * opencode's native `task` / `task_status` sub-agent tools — denied for EVERY
 * OmP agent. All sub-agent spawning flows exclusively through `omp_task_launch`
 * (BackgroundManager + events.log + concurrency queue). The native `task` tool
 * would bypass all of that, so no agent — leaf or spawner — may use it. The
 * strategist still spawns Exploiter, but only via `omp_task_launch`. (The
 * orchestrator, a TUI-selected primary agent, is denied these separately on its
 * own AgentConfig `permission`, since this restriction map only applies to
 * agents spawned through `omp_task_launch`.)
 */
const NATIVE_TASK_DENY = {
  task: false,
  task_status: false,
} as const

/**
 * Submit protocol tool ACL (T42). Every sub-agent delivers its result via
 * `omp_task_submit` and may self-terminate via `omp_task_terminate` (called
 * with no task_id). `omp_task_resume` + parent-`terminate` (with a task_id) are
 * parent-only — leaf agents deny `resume` here; the strategist (which drives an
 * exploiter retry loop) gets `resume: true` in its own map. `submit` /
 * `terminate` are one shared surface, so they stay allowed for all.
 */
const SUBMIT_LEAF = {
  omp_task_submit: true,
  omp_task_terminate: true,
  omp_task_resume: false,
} as const

const AGENT_RESTRICTIONS: Record<string, Record<string, boolean>> = {
  "omp-setup": {
    // Leaf agent — single-transaction Phase 0 ground-work. No
    // child spawning. State writer (Phase 0) → patch_state allowed.
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
    ...SUBMIT_LEAF,
    ...DB_WRITE_DENY_CANDIDATE_CHALLENGE,
  },
  "omp-reverser": {
    // Leaf agent. State writer (own artifacts metadata) → patch_state allowed.
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
    ...SUBMIT_LEAF,
    ...DB_WRITE_DENY_CANDIDATE_CHALLENGE,
  },
  "omp-vulnhunter": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
    ...SUBMIT_LEAF,
    ...DB_WRITE_DENY_ALL,
  },
  "omp-strategist": {
    omp_task_launch: true,
    omp_task_wait_all: true,
    omp_task_wait_any: true,
    omp_task_cancel: true,
    // Submit protocol: SA submits its own result AND drives exploiters
    // (resume + parent-terminate).
    omp_task_submit: true,
    omp_task_resume: true,
    omp_task_terminate: true,
    ...DB_WRITE_DENY_ALL,
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
    ...SUBMIT_LEAF,
    ...DB_WRITE_DENY_ALL,
  },
  "omp-exploiter-mode-2": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
    ...SUBMIT_LEAF,
    ...DB_WRITE_DENY_ALL,
  },
  "omp-exploiter-mode-0": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
    ...SUBMIT_LEAF,
    ...DB_WRITE_DENY_ALL,
  },
  "omp-exploiter-mode-9": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
    ...SUBMIT_LEAF,
    ...DB_WRITE_DENY_ALL,
  },
  // GPT/principle-driven prompt variants of mode-1 / mode-2. Same leaf
  // restriction shape — listed individually so the unknown-agent fallback
  // (`{}` = full access) never relaxes them. Decision: `.omc/decisions.md` #5.
  "omp-exploiter-mode-1-gpt": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
    ...SUBMIT_LEAF,
    ...DB_WRITE_DENY_ALL,
  },
  "omp-exploiter-mode-2-gpt": {
    omp_task_launch: false,
    omp_task_wait_all: false,
    omp_task_wait_any: false,
    omp_task_cancel: false,
    ...SUBMIT_LEAF,
    ...DB_WRITE_DENY_ALL,
  },
}

/**
 * Get tool restriction map for an agent.
 * Returns `{}` for unknown agents (full access) — including the orchestrator,
 * which is never spawned via `omp_task_launch` (its native-task deny lives on
 * its own AgentConfig `permission`). Every KNOWN OmP agent additionally gets
 * opencode's native `task` / `task_status` denied (`NATIVE_TASK_DENY`), so no
 * sub-agent can bypass the `omp_task_launch` pipeline.
 */
export function getAgentToolRestrictions(
  agentName: string,
): Record<string, boolean> {
  const base = AGENT_RESTRICTIONS[agentName]
  if (!base) return {}
  return { ...NATIVE_TASK_DENY, ...base }
}
