/**
 * omp_load_challenge — challenge folder bootstrapper tool.
 *
 * Agent surface for the loader: validates that `challenge_dir` exists and
 * is a directory, then bootstraps its `<challenge-dir>/.omp/` layout. **Does
 * not look at the folder contents** — binary / Dockerfile / source detection
 * is the omp-setup agent's job (Phase 0 Detect), per
 * `.omc/specs/contract-load-detect-split.md` (D1, D2).
 *
 * Idempotent: calling again on an already-bootstrapped folder reloads the
 * persisted `ChallengeState` without mutating any file.
 *
 * The orchestrator should call `omp_load_challenge` once at the top of a
 * session, then dispatch the omp-setup subagent.
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import { basename } from "node:path"
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
  /**
   * Optional callback invoked on successful load — used by plugin.ts to
   * register the orchestrator session (TUI plugin's root TreeNode).
   * Tests leave this unset.
   */
  onLoaded?: (input: {
    sessionID: string
    agent: string
    challengeName: string
  }) => void
}

export function createOmpLoadChallengeTool(
  options: OmpLoadChallengeToolOptions = {},
): ToolDefinition {
  return tool({
    description:
      "Bootstrap a CTF challenge folder's .omp/ state directory. " +
      "Pass only the absolute path to the challenge directory — this tool does NOT " +
      "scan the folder contents. Binary / Dockerfile / source identification is the " +
      "omp-setup agent's responsibility (Phase 0 Detect populates " +
      "binary_input_path / dockerfile_path / source_paths via omp_patch_state). " +
      "On success bootstraps <challenge-dir>/.omp/{journal.md, artifacts/, logs/, exploit/} " +
      "layout and returns workspace_root. Idempotent: calling again on an already-loaded " +
      "folder leaves existing files untouched. " +
      "Errors: 'missing-dir' (path does not exist) or 'not-a-directory' (path is a file). " +
      "Empty folders are valid — omp-setup will classify them as challenge_type='unsupported'. " +
      "Always call this BEFORE dispatching the omp-setup subagent.",
    args: {
      challenge_dir: tool.schema
        .string()
        .describe(
          "Absolute path to the challenge directory (the folder that will contain .omp/). " +
            "Must exist and be a directory; otherwise the tool returns a 'missing-dir' or " +
            "'not-a-directory' error.",
        ),
    },
    execute: async ({ challenge_dir }, context) => {
      try {
        const opts: { workspaceRoot?: string } = {}
        if (options.workspacePath !== undefined) {
          opts.workspaceRoot = options.workspacePath
        }
        const result = loadChallengeFolder(challenge_dir, opts)
        if (options.onLoaded && context?.sessionID && context?.agent) {
          options.onLoaded({
            sessionID: context.sessionID,
            agent: context.agent,
            challengeName: basename(challenge_dir),
          })
        }
        return JSON.stringify({
          ok: true,
          workspace_root: result.workspace_root,
          freshlyInitialized: result.freshlyInitialized,
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
