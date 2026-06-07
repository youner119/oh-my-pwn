/**
 * omp-db MCP server — 10 typed, schema-aware tools over the global SQLite DB.
 *
 * Spec: `.omc/specs/deep-interview-database-mcp.md` (T4/T5/T6) +
 * `.omc/specs/challenge-identity-catalog.md` (CI2/CI2b — challenge identity tools).
 *
 * Tools (exposed to opencode as `mcp__omp-db__<name>`):
 *   state/candidate: read_state / patch_state / read_candidate /
 *     create_candidate / patch_candidate / delete_candidate
 *   challenge identity/catalog: register_challenge / lookup_challenge /
 *     read_challenge / update_challenge
 *
 * The tools speak the old nested `ChallengeState` / `VulnCandidate` JSON shape
 * (AC3 — call meaning unchanged from the file-era plugin tools). Write tools
 * carry an `agent_id` enforced by ACL Layer 2 ({@link checkWriteAcl}). Results
 * are JSON strings with the same `{ok:true,…}` / `{error:…}` envelope the
 * file-era tools returned, so the Orchestrator's parsing is unchanged.
 */

import { basename } from "node:path"

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import { z } from "zod"

import {
  ChallengeStateSchema,
  VulnCandidateSchema,
  VulnCandidateSummarySchema,
  type VulnCandidateSummary,
} from "../state/challenge-state"
import type { OmpDatabase } from "../db"
import { checkWriteAcl } from "./acl"
import {
  VULN_CANDIDATE_DETAIL_FIELDS,
  decomposeCandidate,
  decomposeState,
  deleteCandidateRow,
  deleteChallengeRow,
  findChallengeByDir,
  insertCandidate,
  insertChallengeWithState,
  loadCandidate,
  loadChallengeView,
  loadState,
  stateExists,
  updateChallengeRow,
  upsertCandidateSummary,
  writeCandidate,
  writeStateRow,
} from "./mapper"

/** Catalog status enum (challenges.status). */
const CHALLENGE_STATUS = ["unsolved", "solving", "solved", "abandoned"] as const

/**
 * Sanitize a raw name into the `name` part of `<name>_<uuid8>`: lowercase,
 * non-`[a-z0-9_-]` → `-`, collapse, trim, fallback "challenge".
 */
function sanitizeName(raw: string): string {
  const s = raw
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[-_]+|[-_]+$/g, "")
  return s.length > 0 ? s : "challenge"
}

/** Wrap any JSON-able value as an MCP text tool result. */
function jsonResult(value: unknown): CallToolResult {
  return { content: [{ type: "text", text: JSON.stringify(value) }] }
}

/**
 * Build the omp-db MCP server bound to an open Drizzle DB. The caller owns the
 * DB lifecycle (open/close) and the transport (`connect`).
 */
export function createDbMcpServer(db: OmpDatabase): McpServer {
  const server = new McpServer({ name: "omp-db", version: "1.0.0" })

  // ── read_state ──────────────────────────────────────────────────────────
  server.registerTool(
    "read_state",
    {
      description:
        "Read the full ChallengeState for a challenge_id (top-level fields + " +
        "vuln_candidates[] summary array, reassembled from the normalized " +
        "tables). Returns {ok:true, state} or {error:'state_not_found'}.",
      inputSchema: {
        challenge_id: z
          .string()
          .describe("Challenge identifier (surrogate id — NOT a directory path)."),
      },
    },
    async ({ challenge_id }): Promise<CallToolResult> => {
      try {
        const state = await loadState(db, challenge_id)
        if (!state)
          return jsonResult({
            error: "state_not_found",
            message: `No state row for challenge_id ${JSON.stringify(challenge_id)}.`,
          })
        return jsonResult({ ok: true, state })
      } catch (err) {
        return jsonResult({ error: "internal_error", message: String(err) })
      }
    },
  )

  // ── patch_state ─────────────────────────────────────────────────────────
  server.registerTool(
    "patch_state",
    {
      description:
        "Patch (partial update) the ChallengeState. Shallow-merges the patch " +
        "into the existing state (top-level keys replace wholesale — nested " +
        "objects like mitigations are overwritten, not deep-merged). Protected " +
        "fields challenge_dir / schema_version are stripped. The vuln_candidates " +
        "key updates candidate SUMMARY columns (verification_result / " +
        "description / has_poc / counts / agent / combined_from) — detail fields " +
        "in a vuln_candidates row are rejected (use patch_candidate). Summary " +
        "rows UPSERT and preserve detail; ids absent from the array are NOT " +
        "deleted (use delete_candidate). Orchestrator-only (agent_id). Returns " +
        "{ok:true, state} or {error}.",
      inputSchema: {
        challenge_id: z.string().describe("Challenge identifier."),
        patch: z
          .record(z.string(), z.unknown())
          .describe("Partial ChallengeState fields to merge."),
        agent_id: z
          .string()
          .describe("Calling agent identity — must be 'orchestrator' (ACL Layer 2)."),
      },
    },
    async ({ challenge_id, patch, agent_id }): Promise<CallToolResult> => {
      const denial = checkWriteAcl("patch_state", agent_id)
      if (denial) return jsonResult(denial)
      try {
        const current = await loadState(db, challenge_id)
        if (!current)
          return jsonResult({
            error: "state_not_found",
            message: `No state row for challenge_id ${JSON.stringify(challenge_id)}. Seed it first.`,
          })

        const safePatch: Record<string, unknown> = { ...patch }
        delete safePatch["challenge_dir"]
        delete safePatch["schema_version"]

        // Separate the vuln_candidates summary channel from the state merge.
        const vulnRaw = safePatch["vuln_candidates"]
        delete safePatch["vuln_candidates"]

        const summaries: VulnCandidateSummary[] = []
        if (vulnRaw !== undefined) {
          if (!Array.isArray(vulnRaw))
            return jsonResult({
              error: "validation_error",
              message: "vuln_candidates must be an array of summary objects.",
            })
          for (let i = 0; i < vulnRaw.length; i++) {
            const row = vulnRaw[i]
            if (row === null || typeof row !== "object" || Array.isArray(row))
              return jsonResult({
                error: "validation_error",
                message: `vuln_candidates[${i}] must be an object.`,
              })
            const rowObj = row as Record<string, unknown>
            const leaked = VULN_CANDIDATE_DETAIL_FIELDS.filter((f) => f in rowObj)
            if (leaked.length > 0)
              return jsonResult({
                error: "vuln_candidates_detail_in_summary_patch",
                message:
                  `vuln_candidates[${i}]` +
                  (typeof rowObj["id"] === "string" ? ` (id=${rowObj["id"]})` : "") +
                  ` contains detail fields: ${leaked.join(", ")}. ` +
                  "patch_state.vuln_candidates accepts summary fields only. " +
                  "For detail changes use patch_candidate.",
                index: i,
                leaked_fields: leaked,
              })
            const parsed = VulnCandidateSummarySchema.safeParse(rowObj)
            if (!parsed.success)
              return jsonResult({
                error: "validation_error",
                message: parsed.error.message,
              })
            summaries.push(parsed.data)
          }
        }

        const merged = {
          ...current,
          ...safePatch,
          updated_at: new Date().toISOString(),
        }
        const result = ChallengeStateSchema.safeParse(merged)
        if (!result.success)
          return jsonResult({
            error: "validation_error",
            message: result.error.message,
            issues: result.error.issues,
          })

        const decomp = decomposeState(challenge_id, result.data)
        db.transaction((tx) => {
          writeStateRow(tx, decomp)
          for (const summary of summaries) {
            upsertCandidateSummary(tx, challenge_id, summary)
          }
        })

        const updated = await loadState(db, challenge_id)
        return jsonResult({ ok: true, state: updated })
      } catch (err) {
        return jsonResult({ error: "internal_error", message: String(err) })
      }
    },
  )

  // ── read_candidate ──────────────────────────────────────────────────────
  server.registerTool(
    "read_candidate",
    {
      description:
        "Read a candidate's full record (summary + detail) by id. Returns " +
        "{ok:true, candidate} or {error:'candidate_not_found'}. All agents may call.",
      inputSchema: {
        challenge_id: z.string().describe("Challenge identifier."),
        id: z.string().describe("Candidate id."),
      },
    },
    async ({ challenge_id, id }): Promise<CallToolResult> => {
      try {
        const candidate = await loadCandidate(db, challenge_id, id)
        if (!candidate)
          return jsonResult({
            error: "candidate_not_found",
            message: `No candidate ${JSON.stringify(id)} for challenge_id ${JSON.stringify(challenge_id)}.`,
            id,
          })
        return jsonResult({ ok: true, candidate })
      } catch (err) {
        return jsonResult({ error: "internal_error", message: String(err) })
      }
    },
  )

  // ── create_candidate ────────────────────────────────────────────────────
  server.registerTool(
    "create_candidate",
    {
      description:
        "Create a new candidate (summary + detail in one row). Rejects " +
        "{error:'duplicate_id'} if the id already exists, {error:'state_not_found'} " +
        "if the challenge has no state row. Orchestrator-only. Returns {ok:true, candidate}.",
      inputSchema: {
        challenge_id: z.string().describe("Challenge identifier."),
        candidate: z
          .record(z.string(), z.unknown())
          .describe("Full candidate object (summary + detail). id + primitive required."),
        agent_id: z.string().describe("Must be 'orchestrator' (ACL Layer 2)."),
      },
    },
    async ({ challenge_id, candidate, agent_id }): Promise<CallToolResult> => {
      const denial = checkWriteAcl("create_candidate", agent_id)
      if (denial) return jsonResult(denial)
      try {
        const parsed = VulnCandidateSchema.safeParse(candidate)
        if (!parsed.success)
          return jsonResult({
            error: "validation_error",
            message: parsed.error.message,
          })
        const full = parsed.data

        if (!(await stateExists(db, challenge_id)))
          return jsonResult({
            error: "state_not_found",
            message: `No state row for challenge_id ${JSON.stringify(challenge_id)}.`,
          })
        if (await loadCandidate(db, challenge_id, full.id))
          return jsonResult({
            error: "duplicate_id",
            message: `Candidate id ${JSON.stringify(full.id)} already exists.`,
            id: full.id,
          })

        const decomp = decomposeCandidate(challenge_id, full)
        db.transaction((tx) => {
          insertCandidate(tx, decomp)
        })
        return jsonResult({ ok: true, candidate: full })
      } catch (err) {
        return jsonResult({ error: "internal_error", message: String(err) })
      }
    },
  )

  // ── patch_candidate ─────────────────────────────────────────────────────
  server.registerTool(
    "patch_candidate",
    {
      description:
        "Patch a candidate. patch.summary merges summary fields, patch.detail " +
        "merges detail fields; either or both. id cannot change. Orchestrator-only. " +
        "Returns the full updated candidate {ok:true, candidate} or {error}.",
      inputSchema: {
        challenge_id: z.string().describe("Challenge identifier."),
        id: z.string().describe("Candidate id (must already exist)."),
        patch: z
          .object({
            summary: z.record(z.string(), z.unknown()).optional(),
            detail: z.record(z.string(), z.unknown()).optional(),
          })
          .describe("Patch payload {summary?, detail?}."),
        agent_id: z.string().describe("Must be 'orchestrator' (ACL Layer 2)."),
      },
    },
    async ({ challenge_id, id, patch, agent_id }): Promise<CallToolResult> => {
      const denial = checkWriteAcl("patch_candidate", agent_id)
      if (denial) return jsonResult(denial)
      try {
        const existing = await loadCandidate(db, challenge_id, id)
        if (!existing)
          return jsonResult({
            error: "candidate_not_found",
            message: `No candidate ${JSON.stringify(id)} for challenge_id ${JSON.stringify(challenge_id)}.`,
            id,
          })

        const summaryPatch = (patch.summary ?? {}) as Record<string, unknown>
        const detailPatch = (patch.detail ?? {}) as Record<string, unknown>
        const merged = {
          ...existing,
          ...summaryPatch,
          ...detailPatch,
          id: existing.id,
        }
        const result = VulnCandidateSchema.safeParse(merged)
        if (!result.success)
          return jsonResult({
            error: "validation_error",
            message: result.error.message,
          })

        const decomp = decomposeCandidate(challenge_id, result.data)
        db.transaction((tx) => {
          writeCandidate(tx, decomp)
        })
        return jsonResult({ ok: true, candidate: result.data })
      } catch (err) {
        return jsonResult({ error: "internal_error", message: String(err) })
      }
    },
  )

  // ── delete_candidate ────────────────────────────────────────────────────
  server.registerTool(
    "delete_candidate",
    {
      description:
        "Delete a candidate (row + cascade FK arrays). Returns {ok:true, deleted:true} " +
        "or {error:'candidate_not_found'}. Orchestrator-only.",
      inputSchema: {
        challenge_id: z.string().describe("Challenge identifier."),
        id: z.string().describe("Candidate id."),
        agent_id: z.string().describe("Must be 'orchestrator' (ACL Layer 2)."),
      },
    },
    async ({ challenge_id, id, agent_id }): Promise<CallToolResult> => {
      const denial = checkWriteAcl("delete_candidate", agent_id)
      if (denial) return jsonResult(denial)
      try {
        const deleted = db.transaction((tx) =>
          deleteCandidateRow(tx, challenge_id, id),
        )
        if (!deleted)
          return jsonResult({
            error: "candidate_not_found",
            message: `No candidate ${JSON.stringify(id)} to delete.`,
            id,
          })
        return jsonResult({ ok: true, deleted: true, id })
      } catch (err) {
        return jsonResult({ error: "internal_error", message: String(err) })
      }
    },
  )

  // ── register_challenge ──────────────────────────────────────────────────
  server.registerTool(
    "register_challenge",
    {
      description:
        "Register a NEW challenge (identity + catalog) and seed its initial " +
        "state row. Pure create: if a challenge already exists at `dir`, returns " +
        "{error:'challenge_exists', challenge_id} WITHOUT writing — use " +
        "lookup_challenge for the dir→id idempotency check before calling this. " +
        "Otherwise mints challenge_id = '<name>_<uuid8>' (name = sanitized `name` " +
        "or basename(dir)) and creates the challenges + initial state rows. " +
        "Allowed agents: orchestrator, setup (fresh registration runs inside " +
        "setup's Phase 0). Returns {ok, challenge_id, challenge}.",
      inputSchema: {
        dir: z.string().describe("Absolute challenge directory path."),
        workspace_root: z
          .string()
          .optional()
          .describe("Plugin workspace mount source, seeded into the state row."),
        name: z
          .string()
          .optional()
          .describe("Human label; defaults to basename(dir). Sanitized."),
        agent_id: z
          .string()
          .describe("Must be 'orchestrator' or 'setup' (ACL Layer 2)."),
      },
    },
    async ({ dir, workspace_root, name, agent_id }): Promise<CallToolResult> => {
      const denial = checkWriteAcl("register_challenge", agent_id)
      if (denial) return jsonResult(denial)
      try {
        const existing = await findChallengeByDir(db, dir)
        if (existing) {
          return jsonResult({
            error: "challenge_exists",
            challenge_id: existing.challengeId,
            message:
              `A challenge is already registered at dir ${JSON.stringify(dir)} ` +
              `(challenge_id ${existing.challengeId}). Use lookup_challenge to ` +
              "resolve dir→id, or read_challenge for the full record.",
          })
        }
        const base = sanitizeName(name ?? basename(dir))
        const uuid8 = crypto.randomUUID().replace(/-/g, "").slice(0, 8)
        const challengeId = `${base}_${uuid8}`
        insertChallengeWithState(db, {
          challengeId,
          name: base,
          dir,
          workspaceRoot: workspace_root,
          now: new Date(),
        })
        const challenge = await loadChallengeView(db, challengeId)
        return jsonResult({ ok: true, challenge_id: challengeId, challenge })
      } catch (err) {
        return jsonResult({ error: "internal_error", message: String(err) })
      }
    },
  )

  // ── lookup_challenge ────────────────────────────────────────────────────
  server.registerTool(
    "lookup_challenge",
    {
      description:
        "Resolve a challenge directory to its challenge_id — the dir→id " +
        "idempotency lookup. Read-only, all agents may call (no agent_id). " +
        "Returns {ok:true, found:true, challenge_id} when a challenge is " +
        "registered at `dir`, else {ok:true, found:false}. Call this at session " +
        "start to decide fresh (found:false → register_challenge) vs reload " +
        "(found:true → reuse the id). If a dir holds multiple historical rows " +
        "(after a move + re-register), the most recently created wins.",
      inputSchema: {
        dir: z.string().describe("Absolute challenge directory path."),
      },
    },
    async ({ dir }): Promise<CallToolResult> => {
      try {
        const existing = await findChallengeByDir(db, dir)
        if (!existing) return jsonResult({ ok: true, found: false })
        return jsonResult({ ok: true, found: true, challenge_id: existing.challengeId })
      } catch (err) {
        return jsonResult({ error: "internal_error", message: String(err) })
      }
    },
  )

  // ── read_challenge ──────────────────────────────────────────────────────
  server.registerTool(
    "read_challenge",
    {
      description:
        "Read a challenge's catalog record (challenge_id / name / dir / source / " +
        "status / solved_at / notes / timestamps) plus a derived `category` " +
        "(from state.challenge_type / unsupported_kind). All agents may call. " +
        "Returns {ok, challenge} or {error:'challenge_not_found'}.",
      inputSchema: {
        challenge_id: z.string().describe("Challenge identifier."),
      },
    },
    async ({ challenge_id }): Promise<CallToolResult> => {
      try {
        const challenge = await loadChallengeView(db, challenge_id)
        if (!challenge)
          return jsonResult({
            error: "challenge_not_found",
            message: `No challenge ${JSON.stringify(challenge_id)}.`,
            challenge_id,
          })
        return jsonResult({ ok: true, challenge })
      } catch (err) {
        return jsonResult({ error: "internal_error", message: String(err) })
      }
    },
  )

  // ── update_challenge ────────────────────────────────────────────────────
  server.registerTool(
    "update_challenge",
    {
      description:
        "Update a challenge's catalog fields (status / source / notes / " +
        "solved_at). Identity fields (challenge_id / name / dir / created_at) are " +
        "immutable here. source/notes/solved_at accept null to clear. " +
        "Orchestrator-only. Returns {ok, challenge} or {error:'challenge_not_found'}.",
      inputSchema: {
        challenge_id: z.string().describe("Challenge identifier."),
        patch: z
          .object({
            status: z.enum(CHALLENGE_STATUS).optional(),
            source: z.string().nullable().optional(),
            notes: z.string().nullable().optional(),
            solved_at: z.string().nullable().optional(),
          })
          .describe("Catalog fields to update (only present keys are written)."),
        agent_id: z.string().describe("Must be 'orchestrator' (ACL Layer 2)."),
      },
    },
    async ({ challenge_id, patch, agent_id }): Promise<CallToolResult> => {
      const denial = checkWriteAcl("update_challenge", agent_id)
      if (denial) return jsonResult(denial)
      try {
        const mapped: {
          status?: string
          source?: string | null
          notes?: string | null
          solvedAt?: string | null
        } = {}
        if (patch.status !== undefined) mapped.status = patch.status
        if ("source" in patch) mapped.source = patch.source ?? null
        if ("notes" in patch) mapped.notes = patch.notes ?? null
        if ("solved_at" in patch) mapped.solvedAt = patch.solved_at ?? null

        const existed = updateChallengeRow(db, challenge_id, mapped, new Date())
        if (!existed)
          return jsonResult({
            error: "challenge_not_found",
            message: `No challenge ${JSON.stringify(challenge_id)} to update.`,
            challenge_id,
          })
        const challenge = await loadChallengeView(db, challenge_id)
        return jsonResult({ ok: true, challenge })
      } catch (err) {
        return jsonResult({ error: "internal_error", message: String(err) })
      }
    },
  )

  // ── delete_challenge ────────────────────────────────────────────────────
  server.registerTool(
    "delete_challenge",
    {
      description:
        "Permanently delete a challenge and ALL its data — the catalog record, " +
        "the state row, every candidate, and all dependent FK rows (cascade). " +
        "Use for a same-challenge fresh restart: delete, then re-register via " +
        "setup. **Irreversible.** Orchestrator-only. Returns {ok, deleted:" +
        "{challenge_id, candidates_removed}} or {error:'challenge_not_found'}.",
      inputSchema: {
        challenge_id: z
          .string()
          .describe("Challenge identifier (surrogate id — NOT a directory path)."),
        agent_id: z.string().describe("Must be 'orchestrator' (ACL Layer 2)."),
      },
    },
    async ({ challenge_id, agent_id }): Promise<CallToolResult> => {
      const denial = checkWriteAcl("delete_challenge", agent_id)
      if (denial) return jsonResult(denial)
      try {
        const { existed, candidatesRemoved } = deleteChallengeRow(db, challenge_id)
        if (!existed)
          return jsonResult({
            error: "challenge_not_found",
            message: `No challenge ${JSON.stringify(challenge_id)} to delete.`,
            challenge_id,
          })
        return jsonResult({
          ok: true,
          deleted: { challenge_id, candidates_removed: candidatesRemoved },
        })
      } catch (err) {
        return jsonResult({ error: "internal_error", message: String(err) })
      }
    },
  )

  return server
}
