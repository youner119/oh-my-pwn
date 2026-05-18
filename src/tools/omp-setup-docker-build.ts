/**
 * omp_setup_docker_build — Phase 1 of omp-setup agent (Docker build).
 *
 * Builds the challenge's Docker image while preserving `binary_input_path`
 * as the immutable input identity. Wraps the existing
 * `src/envsetup/docker-build.ts` library so the heavy lifting (cache
 * detection, build log capture, image tag generation) is shared with the
 * legacy `omp_run_envsetup` path until T19 deprecation.
 *
 * Critical invariant: the agent that calls this tool must NOT have mutated
 * `binary_input_path` before the call. patchelf-in-place is retired —
 * `binary_path` (patched copy) is created in Phase 3, AFTER this build
 * completes, so the image always contains the untouched binary.
 *
 * Status: T02 skeleton — input schema defined, execute returns
 * not_implemented. Full implementation lands in T04.
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import type { DockerRunner } from "../envsetup/docker-runner"

export interface OmpSetupDockerBuildToolOptions {
  /** Inject a fake docker runner for tests. T04 wires this up. */
  runner?: DockerRunner
}

export function createOmpSetupDockerBuildTool(
  _options: OmpSetupDockerBuildToolOptions = {},
): ToolDefinition {
  return tool({
    description:
      "Build the challenge's Docker image. Phase 1 of the omp-setup agent. " +
      "The binary at challenge_dir/<binary_input_rel> MUST remain untouched " +
      "before this call so the image content is deterministic. Returns the " +
      "image tag, whether it came from cache, and the build log path on " +
      "success — or a typed error (docker-not-available, build-failed) on " +
      "failure.",
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
          "Force a fresh `docker build --no-cache`. Default false (use cache when available).",
        ),
      image_tag_hint: tool.schema
        .string()
        .optional()
        .describe(
          "Suggested image tag (e.g. 'omp-<sha8>'). When omitted the builder derives one from binary_input_sha256.",
        ),
    },
    execute: async (args) => {
      return JSON.stringify({
        ok: false,
        error: "not_implemented",
        message:
          "omp_setup_docker_build skeleton — implementation pending (T04).",
        echo_args: args,
      })
    },
  })
}
