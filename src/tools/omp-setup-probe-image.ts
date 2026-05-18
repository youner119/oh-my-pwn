/**
 * omp_setup_probe_image — Phase 2 of omp-setup agent (Dependency discovery).
 *
 * Run an arbitrary command inside a built Docker image and return stdout /
 * stderr / exit_code. Used by the setup agent to locate non-standard
 * library paths (`ldconfig -p | grep libz`, `find / -name 'libfoo.so*'`,
 * `ls /opt/lib`, etc.) when the canonical glibc candidate paths miss.
 *
 * The probe runs via `docker run --rm --entrypoint sh <image> -c <command>`
 * so the image's CMD/ENTRYPOINT is bypassed (we do not want the challenge
 * binary to start).
 *
 * Status: T02 skeleton — input schema defined, execute returns
 * not_implemented. Full implementation lands in T05.
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import type { DockerRunner } from "../envsetup/docker-runner"

export interface OmpSetupProbeImageToolOptions {
  /** Inject a fake docker runner for tests. T05 wires this up. */
  runner?: DockerRunner
}

export function createOmpSetupProbeImageTool(
  _options: OmpSetupProbeImageToolOptions = {},
): ToolDefinition {
  return tool({
    description:
      "Run an arbitrary shell command inside a built Docker image and return " +
      "stdout / stderr / exit_code. Phase 2 of the omp-setup agent uses this " +
      "to discover non-standard library paths (`ldconfig -p`, `find /lib*`, " +
      "etc.) when canonical paths miss. The probe always runs --rm and " +
      "bypasses the image's CMD/ENTRYPOINT, so it is safe to call repeatedly. " +
      "Do not use this for binary execution — it is for image inspection only.",
    args: {
      image_tag: tool.schema
        .string()
        .describe(
          "Docker image tag or id (returned by omp_setup_docker_build).",
        ),
      command: tool.schema
        .string()
        .describe(
          "Shell command line to execute inside the image. Passed verbatim to `sh -c`. " +
            "Examples: 'ldconfig -p | grep libz', 'find /lib /usr/lib -name \"libcrypto*\" 2>/dev/null', " +
            "'cat /etc/os-release'.",
        ),
      timeout_ms: tool.schema
        .number()
        .optional()
        .describe(
          "Probe wall-clock timeout in milliseconds. Default 30000.",
        ),
    },
    execute: async (args) => {
      return JSON.stringify({
        ok: false,
        error: "not_implemented",
        message:
          "omp_setup_probe_image skeleton — implementation pending (T05).",
        echo_args: args,
      })
    },
  })
}
