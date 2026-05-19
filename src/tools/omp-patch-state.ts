/**
 * omp_patch_state — challenge state 부분 업데이트 tool.
 *
 * 에이전트가 작업을 완료한 뒤 state.json의 특정 필드를 업데이트할 때 사용.
 * patch 객체를 기존 state에 shallow merge 후 Zod 검증을 거쳐 atomic write.
 * Zod 검증 실패 시 파일을 건드리지 않고 에러 반환.
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import { loadChallengeState, saveChallengeState, ChallengeStateLoadError } from "../state/io"
import { ChallengeStateSchema } from "../state/challenge-state"

export const ompPatchStateTool: ToolDefinition = tool({
  description:
    "Patch (partial update) the ChallengeState for a challenge directory. " +
    "Merges the given patch object into the existing state and saves atomically with Zod validation. " +
    "Use this after completing work to record results — e.g. after Reverser analysis, patch " +
    "{ reverser_summary_path, reverser_analyzed_at }. " +
    "Only provide fields you want to change; all other fields are preserved. " +
    "Protected fields (auto-stripped from patch): challenge_dir, schema_version, " +
    "binary_input_path, binary_input_sha256 — these are loader-only invariants. " +
    "binary_path is NOT protected (omp-setup agent rewrites it to the patched copy " +
    "in Phase 3 per spec D3). " +
    "Returns the updated state on success, or an error object on failure.",
  args: {
    challenge_dir: tool.schema
      .string()
      .describe("Absolute path to the challenge directory (parent of .omp/)"),
    patch: tool.schema
      .record(tool.schema.string(), tool.schema.unknown())
      .describe(
        "Partial ChallengeState fields to merge into the existing state. " +
        "Example: { \"reverser_summary_path\": \"/path/to/reverser-analysis.json\", " +
        "\"reverser_analyzed_at\": \"2026-04-12T00:00:00.000Z\" }",
      ),
  },
  execute: async ({ challenge_dir, patch }) => {
    // 1. 기존 state 로드
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
        message: `No .omp/state.json found in ${challenge_dir}. Run the loader (T03) first.`,
      })
    }

    // 2. patch를 shallow merge — loader-only invariants 만 protected.
    //    challenge_dir / schema_version 은 loader 초기 시딩 외에 변경 금지.
    //    binary_input_path / binary_input_sha256 도 input identity invariant
    //    (T01.6 의 setup-gate idempotency 가 의존). binary_path 는 omp-setup
    //    agent (envsetup 재설계 spec D3) 가 Phase 3 에서 patched copy 경로로
    //    update 해야 하므로 stripping 대상에서 제외.
    const safePatch = { ...patch }
    delete safePatch["challenge_dir"]
    delete safePatch["schema_version"]
    delete safePatch["binary_input_path"]
    delete safePatch["binary_input_sha256"]

    const merged = { ...state, ...safePatch }

    // 3. Zod 검증 (saveChallengeState 내부에서도 하지만 에러 메시지를 더 상세히 주기 위해 선행)
    const result = ChallengeStateSchema.safeParse(merged)
    if (!result.success) {
      return JSON.stringify({
        error: "validation_error",
        message: result.error.message,
        issues: result.error.issues,
      })
    }

    // 4. Atomic save
    try {
      const saved = saveChallengeState(result.data)
      return JSON.stringify({ ok: true, state: saved })
    } catch (err) {
      return JSON.stringify({ error: "save_failed", message: String(err) })
    }
  },
})
