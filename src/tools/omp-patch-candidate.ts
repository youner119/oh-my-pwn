/**
 * omp_patch_candidate — atomic summary + detail patch.
 *
 * Spec: `.omc/specs/state-split-vuln-candidates.md` D3 / D6.
 *
 * Orchestrator-only. Sub-agents return `{summary_changes, detail_changes}`
 * in their task result; the Orchestrator calls this tool with
 * `patch = {summary?: summary_changes, detail?: detail_changes}` to persist.
 *
 * Order: detail file first (read → merge → atomic write), then state.json
 * summary row. Each file's own write is atomic (tmp+rename); cross-file
 * atomicity is not guaranteed — detail-then-summary order ensures the worse
 * outcome on partial failure is a stale summary (visibility only), not stale
 * detail (the real data).
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import {
  loadCandidate,
  saveCandidate,
  loadChallengeState,
  saveChallengeState,
  ChallengeStateLoadError,
  CandidateLoadError,
} from "../state/io"
import {
  VulnCandidateSchema,
  VulnCandidateSummarySchema,
  VulnCandidateDetailSchema,
} from "../state/challenge-state"

export const ompPatchCandidateTool: ToolDefinition = tool({
  description:
    "Patch a vulnerability candidate. `patch.summary` merges into " +
    "`state.json.vuln_candidates[<id>]` (state.json write). `patch.detail` " +
    "merges into `.omp/candidates/<id>.json` (detail file write). Either or " +
    "both may be provided; missing side is unchanged. Orchestrator-only. " +
    "Sub-agents return `{summary_changes, detail_changes}` in their task " +
    "result; Orchestrator calls this tool to persist. Returns the full " +
    "updated candidate `{ok:true, candidate}` on success.",
  args: {
    challenge_dir: tool.schema
      .string()
      .describe("Absolute path to the challenge directory (parent of .omp/)."),
    id: tool.schema
      .string()
      .describe(
        "Candidate id (must already exist in state.json.vuln_candidates).",
      ),
    patch: tool.schema
      .object({
        summary: tool.schema
          .record(tool.schema.string(), tool.schema.unknown())
          .optional()
          .describe(
            "Partial summary fields to merge (verification_result / " +
              "description / has_poc / gives_count / needs_count / etc).",
          ),
        detail: tool.schema
          .record(tool.schema.string(), tool.schema.unknown())
          .optional()
          .describe(
            "Partial detail fields to merge (rationale / verification_blockers " +
              "/ gives / needs / poc_script_path / location / libc_range).",
          ),
      })
      .describe(
        "Patch payload — `{summary?, detail?}`. Both optional but at least one " +
          "should be provided (an empty patch is a no-op).",
      ),
  },
  execute: async ({ challenge_dir, id, patch }) => {
    const summaryPatch = (patch.summary ?? {}) as Record<string, unknown>
    const detailPatch = (patch.detail ?? {}) as Record<string, unknown>

    // 1. Load existing detail (also exists-check).
    let existing
    try {
      existing = loadCandidate(challenge_dir, id)
    } catch (err) {
      if (err instanceof CandidateLoadError) {
        return JSON.stringify({
          error: "candidate_corrupt",
          message: err.message,
          candidate_path: err.candidatePath,
        })
      }
      return JSON.stringify({ error: "internal_error", message: String(err) })
    }
    if (existing === null) {
      return JSON.stringify({
        error: "candidate_not_found",
        message: `No candidate file at .omp/candidates/${id}.json`,
        id,
      })
    }

    // 2. Merge + validate. Summary patch may include any summary field; detail
    //    patch any detail field. `id` cannot be changed via patch.
    const merged = {
      ...existing,
      ...summaryPatch,
      ...detailPatch,
      id: existing.id,
    }
    const result = VulnCandidateSchema.safeParse(merged)
    if (!result.success) {
      return JSON.stringify({
        error: "validation_error",
        message: result.error.message,
      })
    }
    const full = result.data

    // 3. Write detail file (atomic). Always — even with summary-only patch we
    //    re-write the detail file to keep state.json/detail consistent under
    //    schema evolution. Cost is one extra rename; acceptable.
    try {
      saveCandidate(challenge_dir, id, full)
    } catch (err) {
      return JSON.stringify({
        error: "candidate_write_failed",
        message: String(err),
      })
    }

    // 4. Update state.json summary row if summary fields changed.
    if (Object.keys(summaryPatch).length > 0) {
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
      const idx = state.vuln_candidates.findIndex((c) => c.id === id)
      if (idx < 0) {
        return JSON.stringify({
          error: "summary_row_missing",
          message: `Detail file exists but state.json.vuln_candidates lacks row for ${id}. Out-of-sync state — orchestrator must reconcile.`,
          id,
        })
      }
      const summary = VulnCandidateSummarySchema.parse(full)
      const updated = [...state.vuln_candidates]
      updated[idx] = summary
      try {
        saveChallengeState({ ...state, vuln_candidates: updated })
      } catch (err) {
        return JSON.stringify({
          error: "state_write_failed",
          message: `Detail saved but state.json summary update failed: ${String(err)}`,
        })
      }
    }

    return JSON.stringify({ ok: true, candidate: full })
  },
})

// Silence unused — kept for explicit type intent.
void VulnCandidateDetailSchema
