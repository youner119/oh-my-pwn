/**
 * omp_load_challenge — T03 challenge folder loader tool.
 *
 * 에이전트(omp-orchestrator)가 새 challenge를 처음 로드할 때 사용.
 * bash로 직접 파일 탐색하지 않고 이 tool을 호출할 것.
 *
 * 내부적으로 `loadChallengeFolder()` (src/loader/load-challenge-folder.ts)를
 * 호출하는 thin wrapper. 입력 계약 검증 — 디렉토리 존재, Dockerfile 발견,
 * ELF 바이너리 정확히 1개 — 을 거쳐 `<challenge-dir>/.omp/` 레이아웃을
 * 부트스트랩한다. 재실행 시 load-or-init (기존 state.json 존재 시 그대로 로드
 * 후 sha drift만 journal에 기록, state는 절대 덮어쓰지 않음).
 *
 * 성공 시 state + freshlyInitialized + shaDrift 플래그 반환.
 * 실패 시 ChallengeLoadError.kind + detail을 JSON으로 평탄화. 특히
 * `ambiguous-binary` 에러는 `detail.candidates` 목록을 동봉하므로 orchestrator가
 * 사용자에게 "이 중 어느 게 challenge binary인가요?" 하고 물어본 뒤
 * `binary` hint를 채워서 재호출할 수 있다.
 *
 * 이 tool 이후 반드시 `omp_run_envsetup`을 호출해 EnvSetup 파이프라인을 진행할 것.
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import { loadChallengeFolder } from "../loader/load-challenge-folder"
import { ChallengeLoadError } from "../loader/challenge-load-error"

export interface OmpLoadChallengeToolOptions {
  /**
   * Absolute host path to the plugin's workspace mount source
   * (`<plugin-root>/workspace/`). When set, the loader seeds
   * `state.workspace_root` so downstream agents (Setup, Reverser, VH, SA,
   * Exploiter) can derive per-challenge container paths without inferring
   * the plugin root themselves. plugin.ts wires `OMP_WORKSPACE_PATH` here.
   * When omitted (tests / standalone CLI), `state.workspace_root` stays
   * undefined.
   */
  workspacePath?: string
}

export function createOmpLoadChallengeTool(
  options: OmpLoadChallengeToolOptions = {},
): ToolDefinition {
  return tool({
    description:
      "Load and validate a CTF challenge folder, bootstrapping its .omp/ state directory. " +
      "This is the ONLY correct way to initialize a new challenge — do NOT scan the folder with " +
      "bash/ls/find. The loader enforces the input contract (directory exists, Dockerfile present, " +
      "exactly one executable ELF binary), computes the binary's SHA-256, and creates " +
      "<challenge-dir>/.omp/{state.json, journal.md, artifacts/, logs/, exploit/}. " +
      "Idempotent: calling it again on an already-loaded folder reloads state and records sha drift " +
      "in the journal without mutating state.json. " +
      "Call this BEFORE the omp-setup agent runs. " +
      "On ambiguous-binary error, the `detail.candidates` list tells you what to ask the user about — " +
      "then re-call with a `binary` hint. Same for dockerfile disambiguation.",
    args: {
      challenge_dir: tool.schema
        .string()
        .describe(
          "Absolute path to the challenge directory (the folder that will contain .omp/)",
        ),
      binary: tool.schema
        .string()
        .optional()
        .describe(
          "Optional disambiguation hint for the challenge binary. Basename relative to " +
            "challenge_dir (e.g. 'chall'), relative subpath (e.g. 'deploy/chall'), or absolute path. " +
            "Pass this when auto-detection returned ambiguous-binary, or when the binary lives in a " +
            "subdirectory like 'deploy/'.",
        ),
      dockerfile: tool.schema
        .string()
        .optional()
        .describe(
          "Optional disambiguation hint for the Dockerfile. Same forms as `binary`. " +
            "Pass this when the Dockerfile lives in a subdirectory (e.g. 'deploy/Dockerfile') " +
            "or has a non-standard name (e.g. 'Dockerfile.prod'). When omitted, the loader looks " +
            "for 'Dockerfile' or 'dockerfile' in the immediate children of challenge_dir.",
        ),
    },
    execute: async ({ challenge_dir, binary, dockerfile }) => {
      try {
        const opts: {
          binary?: string
          dockerfile?: string
          workspaceRoot?: string
        } = {}
        if (binary !== undefined) opts.binary = binary
        if (dockerfile !== undefined) opts.dockerfile = dockerfile
        if (options.workspacePath !== undefined) {
          opts.workspaceRoot = options.workspacePath
        }
        const result = loadChallengeFolder(challenge_dir, opts)
        return JSON.stringify({
          ok: true,
          state: result.state,
          freshlyInitialized: result.freshlyInitialized,
          shaDrift: result.shaDrift,
        })
      } catch (err) {
        if (err instanceof ChallengeLoadError) {
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
}

/**
 * @deprecated Use {@link createOmpLoadChallengeTool} so the plugin can wire
 * `workspacePath` into `state.workspace_root`. The constant remains so
 * existing callers (tests, standalone tools) keep compiling — it just
 * cannot seed `workspace_root`.
 */
export const ompLoadChallengeTool: ToolDefinition = createOmpLoadChallengeTool()
