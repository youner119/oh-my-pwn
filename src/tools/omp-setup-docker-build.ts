/**
 * omp_setup_docker_build — Phase 1 of omp-setup agent (Docker build).
 *
 * Builds the challenge's Docker image while preserving `binary_input_path`
 * as the immutable input identity. Wraps the existing
 * `src/envsetup/docker-build.ts` library so the heavy lifting (cache
 * detection, build log capture, image tag derivation) is shared with the
 * legacy `omp_run_envsetup` path until T19 deprecation.
 *
 * Image tag policy (post DB-cutover): `image_tag_hint` is required. `state.json`
 * no longer seeds the binary sha, so the sha-derived `omp-<sha8>` fallback is
 * gone. The setup agent reads `binary_input_sha256` via
 * `mcp__omp-db__read_state` and passes a meaningful tag (`"afterimage"`,
 * `"kaleido"`, `"omp/pwno-mcp:dev"`). When the hint is absent the tool refuses
 * with `image_tag_required`.
 *
 * Critical invariant: the agent calling this tool must NOT have mutated
 * `binary_input_path` before the call. patchelf-in-place is retired —
 * `binary_path` (patched copy) is created in Phase 3, AFTER this build
 * completes, so the image always contains the untouched input binary.
 */

import { isAbsolute, join } from "node:path"
import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import { dockerBuildImage } from "../envsetup/docker-build"
import {
  realDockerRunner,
  type DockerRunner,
} from "../envsetup/docker-runner"
import { EnvSetupError } from "../envsetup/envsetup-error"

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
      "before this call so the image content is deterministic. image_tag_hint " +
      "is REQUIRED — state.json no longer seeds the binary sha, so there is no " +
      "sha-derived default. The setup agent reads binary_input_sha256 via " +
      "mcp__omp-db__read_state and passes a meaningful tag. Builds the Dockerfile " +
      "at challenge_dir/<dockerfile_rel or 'Dockerfile'>. Pass force_rebuild=true " +
      "to force a fresh build (--no-cache). Returns image_tag and the build log " +
      "path on success — or a typed error (image_tag_required, " +
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
          "Force a fresh build — passes --no-cache to docker build. Default false " +
            "(docker's own layer cache already reuses unchanged layers).",
        ),
      image_tag_hint: tool.schema
        .string()
        .optional()
        .describe(
          "REQUIRED. Explicit image tag (e.g. 'afterimage', 'kaleido', 'omp/pwno-mcp:dev'). " +
            "The tool returns image_tag_required when omitted. Must be a valid Docker tag.",
        ),
      dockerfile_rel: tool.schema
        .string()
        .optional()
        .describe(
          "Dockerfile path relative to challenge_dir. Default 'Dockerfile'. The " +
            "setup agent passes the path it found in Phase 0 Detect when it differs.",
        ),
    },
    execute: async ({ challenge_dir, force_rebuild, image_tag_hint, dockerfile_rel }) => {
      try {
        if (!isAbsolute(challenge_dir)) {
          return JSON.stringify({
            ok: false,
            error: "challenge_dir_not_absolute",
            message: `challenge_dir must be an absolute path; got "${challenge_dir}".`,
          })
        }

        // Image tag policy — hint is now required. state.json no longer
        // seeds the binary sha, so there is no sha-derived fallback.
        const hint = image_tag_hint?.trim()
        if (hint === undefined || hint === "") {
          return JSON.stringify({
            ok: false,
            error: "image_tag_required",
            message:
              "image_tag_hint is required (state.json no longer seeds binary sha; " +
              "the setup agent reads binary_input_sha256 via mcp__omp-db__read_state and passes the tag).",
          })
        }
        const imageTag = hint

        // Build context = the Dockerfile's folder. Default to the conventional
        // <challenge_dir>/Dockerfile; the setup agent overrides via
        // dockerfile_rel when Phase 0 Detect found it elsewhere.
        const dockerfilePath = join(
          challenge_dir,
          dockerfile_rel?.trim() || "Dockerfile",
        )

        try {
          const result = dockerBuildImage(
            {
              challengeDir: challenge_dir,
              dockerfilePath,
              imageTag,
              forceRebuild: force_rebuild === true,
            },
            runner,
          )
          return JSON.stringify({
            ok: true,
            image_tag: result.imageTag,
            build_log_path: result.buildLogPath,
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
