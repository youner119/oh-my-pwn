/**
 * omp_read_state — challenge state 읽기 tool.
 *
 * 에이전트가 현재 ChallengeState를 읽어 파이프라인의 현재 위치를
 * 파악할 때 사용. state.json이 없으면 에러 반환 (T03가 먼저 실행되어야 함).
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import { loadChallengeState, ChallengeStateLoadError } from "../state/io"

export const ompReadStateTool: ToolDefinition = tool({
  description:
    "Read the current ChallengeState for a challenge directory. " +
    "Returns the full state.json content as JSON. " +
    "Call this first to understand the current pipeline state before doing any work. " +
    "Requires T03 (loadChallengeFolder) to have run first.",
  args: {
    challenge_dir: tool.schema
      .string()
      .describe("Absolute path to the challenge directory (parent of .omp/)"),
  },
  execute: async ({ challenge_dir }) => {
    try {
      const state = loadChallengeState(challenge_dir)
      if (state === null) {
        return JSON.stringify({
          error: "state_not_found",
          message: `No .omp/state.json found in ${challenge_dir}. Run the loader (T03) first.`,
        })
      }
      return JSON.stringify({ ok: true, state })
    } catch (err) {
      if (err instanceof ChallengeStateLoadError) {
        return JSON.stringify({
          error: "state_corrupt",
          message: err.message,
          state_path: err.statePath,
        })
      }
      return JSON.stringify({
        error: "internal_error",
        message: String(err),
      })
    }
  },
})
