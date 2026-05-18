/**
 * omp_setup_inspect_folder — Phase 0 of omp-setup agent (Inspect & Classify).
 *
 * Read-only snapshot of a challenge directory for type classification.
 * Returns folder listing + key file heads + `readelf -d` on the candidate
 * binary + `file` output + Dockerfile text. The setup agent's LLM reasons
 * over this snapshot to decide `challenge_type` ("user-mode-elf" |
 * "unsupported").
 *
 * Status: T02 skeleton — input schema defined, execute returns
 * not_implemented. Full implementation lands in T03 (spec
 * `.omc/specs/deep-interview-envsetup-agent.md`).
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"

export interface OmpSetupInspectFolderToolOptions {
  /** Reserved for T03 — head-byte limit, file extension filter, etc. */
}

export function createOmpSetupInspectFolderTool(
  _options: OmpSetupInspectFolderToolOptions = {},
): ToolDefinition {
  return tool({
    description:
      "Read-only scan of a challenge directory for type classification. Returns " +
      "a structured snapshot (file list, key file heads, readelf -d output on ELF " +
      "candidates, `file` output, Dockerfile text). Phase 0 of the omp-setup agent " +
      "uses this snapshot to decide challenge_type. Does not mutate any file.",
    args: {
      challenge_dir: tool.schema
        .string()
        .describe(
          "Absolute host path to the challenge directory (parent of .omp/).",
        ),
      max_head_bytes: tool.schema
        .number()
        .optional()
        .describe(
          "Max bytes to include from each key file's head (default 4096). " +
            "Used to keep agent context small while still surfacing magic numbers / " +
            "shebangs / Dockerfile FROM lines.",
        ),
    },
    execute: async (args) => {
      return JSON.stringify({
        ok: false,
        error: "not_implemented",
        message:
          "omp_setup_inspect_folder skeleton — implementation pending (T03).",
        echo_args: args,
      })
    },
  })
}
