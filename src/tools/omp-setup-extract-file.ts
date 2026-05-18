/**
 * omp_setup_extract_file — Phase 3 / Phase 5 of omp-setup agent.
 *
 * Single-file copy with two source kinds:
 *
 *   - source="image": `docker cp <container>:<src_path> <dest_path>` from a
 *                     stopped container created on top of the built image.
 *                     Used in Phase 3 to extract NEEDED libraries +
 *                     ld-linux into `.omp/artifacts/`.
 *
 *   - source="host":  plain `cp` between host paths. Used in Phase 5 to
 *                     copy `.omp/artifacts/<lib>` into
 *                     `workspace/<challenge_id>/<lib>` for pwno-mcp.
 *
 * Symlink policy is opt-in per call: `dereference_symlinks: true` follows
 * the symlink and copies the realfile (resulting in a self-contained file
 * with the symlink's basename). `false` copies the symlink itself plus the
 * realfile next to it (so `libz.so.1 → libz.so.1.3` chain is preserved).
 *
 * Status: T02 skeleton — input schema defined, execute returns
 * not_implemented. Full implementation lands in T06.
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import type { DockerRunner } from "../envsetup/docker-runner"

export interface OmpSetupExtractFileToolOptions {
  /** Inject a fake docker runner for tests (image source). T06 wires this up. */
  runner?: DockerRunner
}

export function createOmpSetupExtractFileTool(
  _options: OmpSetupExtractFileToolOptions = {},
): ToolDefinition {
  return tool({
    description:
      "Copy a single file from one of two source kinds to a destination on the " +
      "host. Used in Phase 3 (extract NEEDED libs from Docker image into " +
      ".omp/artifacts/) and Phase 5 (stage to workspace/<id>/ for pwno-mcp). " +
      "Returns { ok, dest_path, sha256, size } on success or a typed error " +
      "(source_missing, docker_cp_failed, host_copy_failed, etc.).",
    args: {
      source: tool.schema
        .string()
        .describe(
          'Source kind: "image" (docker cp from a built image) or "host" (plain host-to-host cp).',
        ),
      image_tag: tool.schema
        .string()
        .optional()
        .describe(
          'Docker image tag or id. Required when source="image", ignored otherwise.',
        ),
      src_path: tool.schema
        .string()
        .describe(
          'Path inside the source location. For source="image" this is an absolute container path ' +
            "(e.g. /lib/x86_64-linux-gnu/libc.so.6). For source=\"host\" this is an absolute host path " +
            "(e.g. /tmp/.omp/artifacts/libc.so.6).",
        ),
      dest_path: tool.schema
        .string()
        .describe(
          "Absolute host destination path. Parent directory is created if missing.",
        ),
      dereference_symlinks: tool.schema
        .boolean()
        .optional()
        .describe(
          "If true, follow symlinks and copy the realfile (`docker cp -L` / `cp -L`). " +
            'If false, preserve the symlink itself. Default true. Set false to keep ' +
            'symlink-chain compatibility (e.g. libbz2.so.1.0 → libbz2.so.1.0.4).',
        ),
    },
    execute: async (args) => {
      return JSON.stringify({
        ok: false,
        error: "not_implemented",
        message:
          "omp_setup_extract_file skeleton — implementation pending (T06).",
        echo_args: args,
      })
    },
  })
}
