/**
 * ACL Layer 2 for the omp-db MCP server.
 *
 * Spec: `.omc/specs/deep-interview-database-mcp.md` (T6, AC4).
 *
 * Two-layer defence keeps the Orchestrator the sole state writer:
 *
 * - **Layer 1** (T9, plugin-side): sub-agent `tools` config never lists the DB
 *   write tools, so opencode does not even expose the call surface.
 * - **Layer 2** (here): the MCP server independently validates the `agent_id`
 *   parameter on every *write* tool and rejects anything but `"orchestrator"`.
 *   This catches a forged / mis-wired call that slips past Layer 1.
 *
 * Read tools (`read_state` / `read_candidate`) take no `agent_id` — all agents
 * may read.
 */

/** Recognised agent identities (the value an agent passes as `agent_id`). */
export const KNOWN_AGENT_IDS = [
  "orchestrator",
  "vulnhunter",
  "strategist",
  "exploiter",
  "reverser",
] as const

export type AgentId = (typeof KNOWN_AGENT_IDS)[number]

/** The sole identity permitted to write state/candidate rows. */
export const SOLE_WRITER: AgentId = "orchestrator"

export interface AclDenial {
  error: "acl_denied"
  message: string
  agent_id: string
}

/**
 * Validate a write tool's `agent_id`. Returns `null` when the call is allowed,
 * or an {@link AclDenial} object (serialise into the tool result) when denied.
 *
 * Denied cases: unknown identity, or a known-but-non-orchestrator agent. Both
 * collapse to `acl_denied` — the server does not leak which check failed.
 */
export function checkWriteAcl(agentId: string): AclDenial | null {
  if (agentId === SOLE_WRITER) return null
  const known = (KNOWN_AGENT_IDS as readonly string[]).includes(agentId)
  return {
    error: "acl_denied",
    message: known
      ? `Agent '${agentId}' is not permitted to write state/candidate rows. ` +
        `Only '${SOLE_WRITER}' may write (sole-writer invariant, ACL Layer 2).`
      : `Unknown agent_id '${agentId}'. Write tools require agent_id='${SOLE_WRITER}'.`,
    agent_id: agentId,
  }
}
