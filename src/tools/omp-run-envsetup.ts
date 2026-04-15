/**
 * omp_run_envsetup — T04 EnvSetup pipeline tool.
 *
 * 에이전트(omp-orchestrator)가 EnvSetup 단계를 실행할 때 사용.
 * bash로 docker/readelf/patchelf를 직접 호출하지 않고 이 tool을 호출할 것.
 *
 * 내부적으로 `runEnvSetup()` (src/envsetup/run-envsetup.ts)을 호출하는 thin wrapper.
 * 모든 deterministic 작업 — docker build, libc/ld 추출, ELF mitigations 파싱,
 * glibc version detect, patchelf interpreter/rpath 재설정 — 은 라이브러리가 담당한다.
 *
 * 성공 시 전체 state + 파이프라인 플래그(rebuilt / staticLinked / patched)를 반환.
 * 실패 시 EnvSetupError.kind + detail 필드를 JSON으로 평탄화해서 반환하므로
 * LLM이 retry / escalate / user 질문 중 어느 path로 갈지 결정할 수 있다.
 *
 * Prerequisites: loadChallengeFolder (T03)가 먼저 실행되어 state.json이 존재해야 함.
 * state가 없으면 `error: "state-missing"` 반환.
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import { runEnvSetup } from "../envsetup/run-envsetup"
import { EnvSetupError } from "../envsetup/envsetup-error"

export const ompRunEnvsetupTool: ToolDefinition = tool({
  description:
    "Run the deterministic EnvSetup pipeline for a challenge directory. " +
    "This is the ONLY way the orchestrator should do EnvSetup — never re-implement " +
    "with bash/docker/readelf calls. The pipeline builds the challenge's Docker image, " +
    "extracts libc/ld, parses ELF mitigations (NX/PIE/Canary/RELRO), detects glibc version, " +
    "and (by default) patches the binary's interpreter + rpath so pwntools loads the docker " +
    "image's libc. All results are persisted to state.json and a summary is appended to journal.md " +
    "automatically. " +
    "Prerequisites: run loadChallengeFolder (T03) first so state.json exists. " +
    "Returns the updated state + pipeline flags on success, or an error object with full " +
    "diagnostic detail (candidate paths tried, exit codes, build log path, etc.) on failure.",
  args: {
    challenge_dir: tool.schema
      .string()
      .describe("Absolute path to the challenge directory (parent of .omp/)"),
    patch: tool.schema
      .boolean()
      .optional()
      .describe(
        "Whether to run patchelf to rewrite the binary's interpreter + rpath to use " +
        "the docker image's libc/ld. Default: true. Pass false to keep the original binary " +
        "unchanged (e.g. when testing against the host's libc). The original is always " +
        "backed up to .omp/artifacts/<basename>.orig before patching.",
      ),
  },
  execute: async ({ challenge_dir, patch }) => {
    try {
      const result = runEnvSetup(challenge_dir, { patch })
      return JSON.stringify({
        ok: true,
        state: result.state,
        rebuilt: result.rebuilt,
        staticLinked: result.staticLinked,
        patched: result.patched,
      })
    } catch (err) {
      if (err instanceof EnvSetupError) {
        return JSON.stringify({
          error: err.kind,
          message: err.message,
          detail: err.detail,
        })
      }
      return JSON.stringify({
        error: "internal_error",
        message: String(err),
      })
    }
  },
})
