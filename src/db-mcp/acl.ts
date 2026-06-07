/**
 * ACL Layer 2 for the omp-db MCP server.
 *
 * Spec: `.omc/specs/deep-interview-database-mcp.md` (T6, AC4 — 2026-06-05 정정).
 *
 * Two-layer defence governs DB writes:
 *
 * - **Layer 1** (T9, plugin-side): each agent's `tools` config lists only the
 *   DB tools it may call — VH/SA/Exploiter get no write tools; setup/reverser
 *   get `patch_state` only; orchestrator gets all.
 * - **Layer 2** (here): the MCP server independently validates `agent_id`
 *   against a **per-tool allowlist** and rejects anything outside it, catching
 *   a forged / mis-wired call that slips past Layer 1.
 *
 * The "sole writer" is per-channel, not global: `patch_state` (state) has three
 * writers (orchestrator + setup in Phase 0 + reverser for its own artifacts
 * metadata; field-level split is prompt policy). `register_challenge` has two
 * (orchestrator + setup, since fresh registration happens inside setup's Phase 0),
 * while candidate writes and `update_challenge` are orchestrator-only. Read tools
 * (`read_state` / `read_candidate` / `read_challenge` / `lookup_challenge`) take no
 * `agent_id` — all agents read.
 */

/** Recognised agent identities (the value an agent passes as `agent_id`). */
export const KNOWN_AGENT_IDS = [
  "orchestrator",
  "setup",
  "reverser",
  "vulnhunter",
  "strategist",
  "exploiter",
] as const

export type AgentId = (typeof KNOWN_AGENT_IDS)[number]

/** Write tools subject to ACL Layer 2. */
export type WriteTool =
  | "patch_state"
  | "create_candidate"
  | "patch_candidate"
  | "delete_candidate"
  | "register_challenge"
  | "update_challenge"
  | "delete_challenge"

/**
 * Per-tool `agent_id` allowlist. `patch_state` is the only multi-writer
 * channel; everything else is orchestrator-only.
 */
export const WRITE_ALLOWLIST: Record<WriteTool, readonly AgentId[]> = {
  patch_state: ["orchestrator", "setup", "reverser"],
  create_candidate: ["orchestrator"],
  patch_candidate: ["orchestrator"],
  delete_candidate: ["orchestrator"],
  register_challenge: ["orchestrator", "setup"],
  update_challenge: ["orchestrator"],
  delete_challenge: ["orchestrator"],
}

export interface AclDenial {
  error: "acl_denied"
  message: string
  agent_id: string
}

/**
 * Validate a write tool's `agent_id` against its allowlist. Returns `null` when
 * allowed, or an {@link AclDenial} (serialise into the tool result) when denied.
 */
export function checkWriteAcl(tool: WriteTool, agentId: string): AclDenial | null {
  const allowed = WRITE_ALLOWLIST[tool]
  if ((allowed as readonly string[]).includes(agentId)) return null
  return {
    error: "acl_denied",
    message:
      `Agent '${agentId}' is not permitted to call ${tool}. ` +
      `Allowed: ${allowed.join(", ")} (ACL Layer 2).`,
    agent_id: agentId,
  }
}
