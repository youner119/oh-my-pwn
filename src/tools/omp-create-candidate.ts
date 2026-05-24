/**
 * omp_create_candidate — append a new candidate (summary + detail) atomically.
 *
 * Spec: `.omc/specs/state-split-vuln-candidates.md` D3 / D6.
 *
 * Orchestrator-only (agent-tool-restrictions ACL). Sub-agents (VH / SA /
 * Exploiter) return `{new_candidate}` in their task result; the Orchestrator
 * calls this tool to persist.
 *
 * Write order: detail file first (atomic tmp+rename), then state.json summary
 * array append. If detail write succeeds but summary append fails, the detail
 * file is left in place (the next create attempt for the same id will error).
 * If a candidate with this id already exists in summary array, the entire
 * operation rejects without touching either file.
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import {
  loadChallengeState,
  saveChallengeState,
  saveCandidate,
  ChallengeStateLoadError,
} from "../state/io"
import {
  VulnCandidateSchema,
  VulnCandidateSummarySchema,
} from "../state/challenge-state"

export const ompCreateCandidateTool: ToolDefinition = tool({
  description:
    "Create a new vulnerability candidate. Writes the detail to " +
    "`.omp/candidates/<id>.json` and appends the summary to " +
    "`state.json.vuln_candidates[]` (atomic per-file). Orchestrator-only. " +
    "Sub-agents (VH / SA / Exploiter) return `{new_candidate}` in their task " +
    "result; the Orchestrator calls this tool to persist. Returns `{ok:true, " +
    "candidate}` on success. Rejects with `{error:'duplicate_id'}` if a " +
    "candidate with the same id already exists.",
  args: {
    challenge_dir: tool.schema
      .string()
      .describe("Absolute path to the challenge directory (parent of .omp/)."),
    candidate: tool.schema
      .record(tool.schema.string(), tool.schema.unknown())
      .describe(
        "Full candidate object — summary fields (id / primitive / " +
          "verification_result / agent / combined_from / description / gives_count " +
          "/ needs_count / has_poc) + detail fields (rationale / " +
          "verification_blockers / gives / needs / poc_script_path / location / " +
          "libc_range / origin_type / derived_from). At minimum `id` and " +
          "`primitive` are required.",
      ),
  },
  execute: async ({ challenge_dir, candidate }) => {
    const parsed = VulnCandidateSchema.safeParse(candidate)
    if (!parsed.success) {
      return JSON.stringify({
        error: "validation_error",
        message: parsed.error.message,
      })
    }
    const full = parsed.data

    let state
    try {
      state = loadChallengeState(challenge_dir)
    } catch (err) {
      if (err instanceof ChallengeStateLoadError) {
        return JSON.stringify({
          error: "state_corrupt",
          message: err.message,
          state_path: err.statePath,
        })
      }
      return JSON.stringify({ error: "internal_error", message: String(err) })
    }
    if (state === null) {
      return JSON.stringify({
        error: "state_not_found",
        message: `No .omp/state.json found in ${challenge_dir}. Run omp_load_challenge first.`,
      })
    }

    if (state.vuln_candidates.some((c) => c.id === full.id)) {
      return JSON.stringify({
        error: "duplicate_id",
        message: `Candidate id ${JSON.stringify(full.id)} already exists in state.json.`,
        id: full.id,
      })
    }

    try {
      saveCandidate(challenge_dir, full.id, full)
    } catch (err) {
      return JSON.stringify({
        error: "candidate_write_failed",
        message: String(err),
      })
    }

    // Derive summary from full candidate. Schema parse strips detail fields.
    const summary = VulnCandidateSummarySchema.parse(full)

    try {
      saveChallengeState({
        ...state,
        vuln_candidates: [...state.vuln_candidates, summary],
      })
    } catch (err) {
      return JSON.stringify({
        error: "state_write_failed",
        message: `Detail saved but state.json summary append failed: ${String(err)}`,
      })
    }

    return JSON.stringify({ ok: true, candidate: full })
  },
})
