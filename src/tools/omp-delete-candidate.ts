/**
 * omp_delete_candidate — remove a candidate (summary row + detail file).
 *
 * Spec: `.omc/specs/state-split-vuln-candidates.md` D3 / D6.
 *
 * Orchestrator-only. Invoked when the orchestrator decides to invalidate a
 * candidate (e.g. a derived candidate proved unsound). Order: summary row
 * first (state.json is the source-of-truth manifest), then detail file. A
 * garbage detail file with no summary row is harmless (loadCandidate returns
 * it only when explicitly queried by id; orchestrator never lists by
 * directory scan).
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import {
  loadChallengeState,
  saveChallengeState,
  deleteCandidate,
  ChallengeStateLoadError,
} from "../state/io"

export const ompDeleteCandidateTool: ToolDefinition = tool({
  description:
    "Delete a vulnerability candidate. Removes the summary row from " +
    "`state.json.vuln_candidates[]` and deletes `.omp/candidates/<id>.json`. " +
    "Orchestrator-only. Returns `{ok:true, id, deleted_detail_file}` where " +
    "`deleted_detail_file` is false if the detail file was already absent.",
  args: {
    challenge_dir: tool.schema
      .string()
      .describe("Absolute path to the challenge directory (parent of .omp/)."),
    id: tool.schema
      .string()
      .describe("Candidate id to remove."),
  },
  execute: async ({ challenge_dir, id }) => {
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
        error: "candidate_not_found",
        message: `No candidate with id ${JSON.stringify(id)} in state.json.vuln_candidates.`,
        id,
      })
    }

    const updated = [
      ...state.vuln_candidates.slice(0, idx),
      ...state.vuln_candidates.slice(idx + 1),
    ]
    try {
      saveChallengeState({ ...state, vuln_candidates: updated })
    } catch (err) {
      return JSON.stringify({
        error: "state_write_failed",
        message: String(err),
      })
    }

    let deletedDetailFile = false
    try {
      deletedDetailFile = deleteCandidate(challenge_dir, id)
    } catch (err) {
      return JSON.stringify({
        error: "candidate_delete_failed",
        message: `Summary row removed but detail file delete failed: ${String(err)}`,
      })
    }

    return JSON.stringify({
      ok: true,
      id,
      deleted_detail_file: deletedDetailFile,
    })
  },
})
