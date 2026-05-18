/**
 * omp_setup_docker_build — Phase 1 of omp-setup agent (Docker build).
 *
 * Builds the challenge's Docker image while preserving `binary_input_path`
 * as the immutable input identity. Wraps the existing
 * `src/envsetup/docker-build.ts` library so the heavy lifting (cache
 * detection, build log capture, image tag derivation) is shared with the
 * legacy `omp_run_envsetup` path until T19 deprecation.
 *
 * Image tag policy (D4 — α decision):
 *
 *   1. If the caller supplies a non-empty `image_tag_hint`, use it as-is.
 *      This is the operator/agent-facing path — meaningful names like
 *      `"afterimage"`, `"kaleido"`, `"omp/pwno-mcp:dev"`.
 *
 *   2. Otherwise fall back to `omp-<sha8>` where `sha8` is the first 8
 *      hex chars of `binary_input_sha256` (preferred — the input identity
 *      contract) or `binary_sha256` (legacy fallback for pre-T01 state).
 *
 *   3. If neither hint nor sha is available, refuse to build and return a
 *      typed error so the caller can either provide a hint or seed the
 *      challenge first.
 *
 * Critical invariant: the agent calling this tool must NOT have mutated
 * `binary_input_path` before the call. patchelf-in-place is retired —
 * `binary_path` (patched copy) is created in Phase 3, AFTER this build
 * completes, so the image always contains the untouched input binary.
 */

import { isAbsolute } from "node:path"
import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import { dockerBuildImage } from "../envsetup/docker-build"
import {
  realDockerRunner,
  type DockerRunner,
} from "../envsetup/docker-runner"
import { EnvSetupError } from "../envsetup/envsetup-error"
import { loadChallengeState } from "../state/io"

export interface OmpSetupDockerBuildToolOptions {
  /** Inject a fake docker runner for tests. Default: real docker CLI. */
  runner?: DockerRunner
}

export function createOmpSetupDockerBuildTool(
  options: OmpSetupDockerBuildToolOptions = {},
): ToolDefinition {
  const runner = options.runner ?? realDockerRunner

  return tool({
    description:
      "Build the challenge's Docker image. Phase 1 of the omp-setup agent. " +
      "The binary at challenge_dir/<binary_input_rel> MUST remain untouched " +
      "before this call so the image content is deterministic. Image tag " +
      "policy: image_tag_hint wins if provided; otherwise omp-<sha8 of " +
      "binary_input_sha256> is derived. Cache is reused when state.docker_image " +
      "already matches and the Dockerfile has not been modified since " +
      "state.updated_at; pass force_rebuild=true to bypass. Returns image_tag, " +
      "whether the result came from cache, and the build log path on " +
      "success — or a typed error (state_missing, no_input_sha, " +
      "docker-not-available, docker-build-failed) on failure.",
    args: {
      challenge_dir: tool.schema
        .string()
        .describe(
          "Absolute host path to the challenge directory (contains Dockerfile and the input binary).",
        ),
      force_rebuild: tool.schema
        .boolean()
        .optional()
        .describe(
          "Force a fresh build — bypass cache reuse even if state.docker_image matches. Default false.",
        ),
      image_tag_hint: tool.schema
        .string()
        .optional()
        .describe(
          "Explicit image tag (e.g. 'afterimage', 'kaleido', 'omp/pwno-mcp:dev'). When omitted, " +
            "tag is derived from binary_input_sha256 as 'omp-<sha8>'. Must be a valid Docker tag.",
        ),
    },
    execute: async ({ challenge_dir, force_rebuild, image_tag_hint }) => {
      try {
        if (!isAbsolute(challenge_dir)) {
          return JSON.stringify({
            ok: false,
            error: "challenge_dir_not_absolute",
            message: `challenge_dir must be an absolute path; got "${challenge_dir}".`,
          })
        }

        const state = loadChallengeState(challenge_dir)
        if (state === null) {
          return JSON.stringify({
            ok: false,
            error: "state_missing",
            message: `No state.json at ${challenge_dir}/.omp/. Run omp_load_challenge first.`,
          })
        }

        // Image tag policy — α: hint wins, else omp-<sha8 from input>.
        const hint = image_tag_hint?.trim()
        const sha = state.binary_input_sha256 ?? state.binary_sha256
        let imageTag: string
        if (hint !== undefined && hint !== "") {
          imageTag = hint
        } else if (sha !== undefined && sha.length >= 8) {
          imageTag = `omp-${sha.slice(0, 8)}`
        } else {
          return JSON.stringify({
            ok: false,
            error: "no_input_sha",
            message:
              "Cannot derive default image tag: state has neither binary_input_sha256 nor binary_sha256. " +
              "Either run omp_load_challenge first to seed binary_input_sha256, or pass image_tag_hint explicitly.",
          })
        }

        try {
          const result = dockerBuildImage(state, runner, {
            imageTagOverride: imageTag,
            forceRebuild: force_rebuild === true,
          })
          return JSON.stringify({
            ok: true,
            image_tag: result.imageTag,
            cached: result.cached,
            build_log_path: result.buildLogPath ?? null,
          })
        } catch (err) {
          if (err instanceof EnvSetupError) {
            return JSON.stringify({
              ok: false,
              error: err.kind,
              message: err.message,
              detail: err.detail,
            })
          }
          throw err
        }
      } catch (err) {
        return JSON.stringify({
          ok: false,
          error: "internal_error",
          message: String(err),
        })
      }
    },
  })
}
