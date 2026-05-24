/**
 * omp_read_candidate — read a candidate's full detail (summary + detail).
 *
 * Spec: `.omc/specs/state-split-vuln-candidates.md` D3.
 *
 * Read-only — available to all OmP agents (sub-agent + orchestrator).
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import { loadCandidate, CandidateLoadError } from "../state/io"

export const ompReadCandidateTool: ToolDefinition = tool({
  description:
    "Read a vulnerability candidate's full record (summary + detail) from " +
    "`.omp/candidates/<id>.json`. Use this when you need the rationale / " +
    "verification_blockers / gives / needs / poc_script_path / location for a " +
    "candidate that appears in `state.json.vuln_candidates[]` (summary only). " +
    "Returns `{ok:true, candidate}` on success, or `{error}` otherwise.",
  args: {
    challenge_dir: tool.schema
      .string()
      .describe("Absolute path to the challenge directory (parent of .omp/)."),
    id: tool.schema
      .string()
      .describe(
        "Candidate id (e.g. 'vuln_4' / 'derived_vuln_4_vuln_16'). Must match the " +
          "summary in state.json. Charset: alphanumeric + underscore + dash.",
      ),
  },
  execute: async ({ challenge_dir, id }) => {
    try {
      const candidate = loadCandidate(challenge_dir, id)
      if (candidate === null) {
        return JSON.stringify({
          error: "candidate_not_found",
          message: `No candidate file at .omp/candidates/${id}.json`,
          id,
        })
      }
      return JSON.stringify({ ok: true, candidate })
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
  },
})
