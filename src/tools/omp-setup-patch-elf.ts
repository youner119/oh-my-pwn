/**
 * omp_setup_patch_elf — Phase 3 / Phase 5 of omp-setup agent.
 *
 * Patchelf wrapper that handles both binary and library cases via a single
 * generalised interface:
 *
 *   - Binary (Phase 3 host-side / Phase 5 workspace-side):
 *       { src_path, dst_path, interpreter, rpath } →
 *       copy src_path → dst_path, then `patchelf --set-interpreter
 *       <interpreter> --set-rpath <rpath> <dst_path>`. src_path is NEVER
 *       mutated.
 *
 *   - Library (Phase 3 / Phase 5):
 *       { src_path, rpath } (no dst_path, no interpreter) →
 *       in-place `patchelf --set-rpath <rpath> <src_path>`. Required
 *       because DT_RUNPATH is NOT transitive — libm/libz/etc. need their
 *       own rpath to find the bundled libc, otherwise they fall back to
 *       host default search path and load the wrong libc.
 *
 * Status: T02 skeleton — input schema defined, execute returns
 * not_implemented. Full implementation lands in T07 (current
 * `src/envsetup/patch-elf.ts` will be adapted to support copy-then-patch).
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import type { SpawnFn } from "../envsetup/patch-elf"

export interface OmpSetupPatchElfToolOptions {
  /** Inject a fake patchelf spawn for tests. T07 wires this up. */
  spawn?: SpawnFn
}

export function createOmpSetupPatchElfTool(
  _options: OmpSetupPatchElfToolOptions = {},
): ToolDefinition {
  return tool({
    description:
      "Run patchelf against an ELF file. Generalised over binary and library: " +
      "supply dst_path + interpreter + rpath for a binary (copy-then-patch); " +
      "omit dst_path and interpreter for a library (in-place rpath only). " +
      "src_path is NEVER mutated when dst_path is supplied — binary_input_path " +
      "invariant. Use this on every extracted ELF in .omp/artifacts/ (Phase 3) " +
      "and on every staged file in workspace/<id>/ (Phase 5) because " +
      "DT_RUNPATH is non-transitive.",
    args: {
      src_path: tool.schema
        .string()
        .describe(
          "Absolute host path to the source ELF (binary or .so). If dst_path is supplied, " +
            "this file is NOT mutated.",
        ),
      dst_path: tool.schema
        .string()
        .optional()
        .describe(
          "Absolute host path where the patched copy is written. When omitted, patchelf runs " +
            "in-place on src_path. Required for binary (Phase 3 / Phase 5 binary case).",
        ),
      interpreter: tool.schema
        .string()
        .optional()
        .describe(
          "Absolute path to set as the ELF interpreter (`patchelf --set-interpreter`). " +
            "Required for binary, omit for library (libraries do not have an interpreter).",
        ),
      rpath: tool.schema
        .string()
        .optional()
        .describe(
          "Absolute path to set as DT_RUNPATH (`patchelf --set-rpath`). Required for both " +
            "binary and library cases — without it ld falls back to host default search.",
        ),
    },
    execute: async (args) => {
      return JSON.stringify({
        ok: false,
        error: "not_implemented",
        message:
          "omp_setup_patch_elf skeleton — implementation pending (T07).",
        echo_args: args,
      })
    },
  })
}
