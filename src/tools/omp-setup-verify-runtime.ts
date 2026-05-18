/**
 * omp_setup_verify_runtime — Phase 4 / Phase 5 of omp-setup agent.
 *
 * Verify that a patched binary actually runs in its target environment:
 *
 *   - mode="host": spawn `<binary_path>` on the host (typically the
 *                  patched copy at .omp/artifacts/<basename>), read stderr
 *                  briefly, and check whether ld successfully resolved
 *                  every NEEDED library. Failure surfaces missing libs in
 *                  evidence.missing_libs.
 *
 *   - mode="container": `docker run --rm <image_tag> <container_binary_path>`
 *                       (or default entrypoint) for a short window. Verifies
 *                       the staged + re-patched binary inside pwno-mcp's
 *                       filesystem layout (`/workspace/<id>/`) actually
 *                       finds its libraries. Optional — useful when the
 *                       agent has staged into workspace/.
 *
 * On failure, the result includes a diagnose block (ldd output, readelf -d
 * RUNPATH/RPATH/NEEDED, image directory listing). The setup agent uses
 * this to fill `setup_unsupported_reason` and stop (D8: diagnose-only,
 * retry 0).
 *
 * Status: T02 skeleton — input schema defined, execute returns
 * not_implemented. Full implementation lands in T08.
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import type { DockerRunner } from "../envsetup/docker-runner"
import type { SpawnFn } from "../envsetup/patch-elf"

export interface OmpSetupVerifyRuntimeToolOptions {
  /** Inject a fake docker runner for tests (container mode). T08 wires this up. */
  runner?: DockerRunner
  /** Inject a fake host spawn for tests (host mode). T08 wires this up. */
  spawn?: SpawnFn
}

export function createOmpSetupVerifyRuntimeTool(
  _options: OmpSetupVerifyRuntimeToolOptions = {},
): ToolDefinition {
  return tool({
    description:
      "Verify a patched binary actually loads + runs in its target environment. " +
      "mode='host' spawns the binary on the host and checks ld resolution; " +
      "mode='container' does the same inside `docker run --rm <image>`. " +
      "Returns { ok, mode, evidence } where evidence includes stdout/stderr " +
      "head, missing_libs (from ldd), and diagnostic detail (readelf -d, image " +
      "listing) when ok=false. The setup agent treats failure as terminal " +
      "(D8 diagnose-only, retry 0) — it fills setup_unsupported_reason and " +
      "stops; no automatic retry / self-fix.",
    args: {
      binary_path: tool.schema
        .string()
        .describe(
          "Absolute host path to the patched binary (or, for mode='container', the host-side path " +
            "used only to derive diagnose info; the actual run uses container_binary_path).",
        ),
      mode: tool.schema
        .string()
        .describe('Verification mode: "host" or "container".'),
      image_tag: tool.schema
        .string()
        .optional()
        .describe(
          "Docker image tag for mode='container'. Ignored for mode='host'.",
        ),
      container_binary_path: tool.schema
        .string()
        .optional()
        .describe(
          'Absolute container path to the binary inside the image (e.g. "/workspace/<id>/prob"). ' +
            "Required for mode='container'.",
        ),
      timeout_ms: tool.schema
        .number()
        .optional()
        .describe(
          "Wall-clock timeout for the verification run. Default 2000ms for host, 5000ms for container.",
        ),
    },
    execute: async (args) => {
      return JSON.stringify({
        ok: false,
        error: "not_implemented",
        message:
          "omp_setup_verify_runtime skeleton — implementation pending (T08).",
        echo_args: args,
      })
    },
  })
}
