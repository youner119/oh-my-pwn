/**
 * omp_setup_patch_elf — Phase 3 / Phase 5 of omp-setup agent.
 *
 * Patchelf wrapper that handles both binary and library cases via a single
 * generalised interface:
 *
 *   - **Binary** (Phase 3 host-side / Phase 5 workspace-side):
 *       { src_path, dst_path, interpreter, replacements } →
 *       copy src_path → dst_path, then
 *       `patchelf --set-interpreter <interpreter>
 *                 --replace-needed <soname> <abs> ...
 *                 <dst_path>`.
 *       src_path is NEVER mutated.
 *
 *   - **Library** (Phase 3 / Phase 5):
 *       { src_path, replacements } →
 *       in-place `patchelf --replace-needed <soname> <abs> ... <src_path>`.
 *       Required because DT_RUNPATH is NOT transitive — libm/libz/etc.
 *       need their own dependency rewrites or they will resolve via host
 *       default search and load the wrong libc.
 *
 * D3 (post-revision): `--set-rpath` is NOT used. NEEDED entries themselves
 * carry absolute paths. This is more explicit (visible via `readelf -d`),
 * immune to `LD_LIBRARY_PATH` interference, and avoids the transitive
 * RUNPATH gotcha entirely.
 */

import { existsSync } from "node:fs"
import { isAbsolute } from "node:path"
import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import { patchElf } from "../envsetup/patch-elf"
import type { SpawnFn } from "../envsetup/patch-elf"
import { EnvSetupError } from "../envsetup/envsetup-error"

export interface OmpSetupPatchElfToolOptions {
  /** Inject a fake patchelf spawn for tests. Default uses spawnSync. */
  spawn?: SpawnFn
}

export function createOmpSetupPatchElfTool(
  options: OmpSetupPatchElfToolOptions = {},
): ToolDefinition {
  return tool({
    description:
      "Run patchelf against an ELF file. Generalised over binary and library: " +
      "supply dst_path + interpreter + replacements for a binary (copy-then-patch); " +
      "omit dst_path and interpreter for a library (in-place, replacements only). " +
      "src_path is NEVER mutated when dst_path is supplied — binary_input_path " +
      "invariant. Replacements is a SONAME → absolute_path map; each entry becomes " +
      "one `--replace-needed <soname> <abs_path>` flag pair, rewriting NEEDED " +
      "entries to absolute paths so ld bypasses any search-path lookup. " +
      "`--set-rpath` is NOT used (D3 — replace-needed is more explicit and immune " +
      "to LD_LIBRARY_PATH interference). Use this on every extracted ELF in " +
      ".omp/artifacts/ (Phase 3) and on every staged file in workspace/<id>/ " +
      "(Phase 5) because DT_RUNPATH is non-transitive.",
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
            "in-place on src_path. Parent directory is auto-created. Required for binary case.",
        ),
      interpreter: tool.schema
        .string()
        .optional()
        .describe(
          "Absolute path to set as the ELF interpreter (`patchelf --set-interpreter`). " +
            "Required for binary, omit for library (libraries do not have an interpreter).",
        ),
      replacements: tool.schema
        .record(tool.schema.string(), tool.schema.string())
        .optional()
        .describe(
          "SONAME → absolute_path map for NEEDED rewrites. Each entry becomes " +
            "one `--replace-needed <soname> <abs_path>` flag pair. Example: " +
            '{"libc.so.6": "/abs/.omp/artifacts/libc.so.6", "libm.so.6": "/abs/.../libm.so.6"}. ' +
            "Use this for both binary (with interpreter) and library (without).",
        ),
    },
    execute: async ({ src_path, dst_path, interpreter, replacements }) => {
      try {
        // ── validation ────────────────────────────────────────────────
        if (!isAbsolute(src_path)) {
          return errorJson({
            error: "src_not_absolute",
            message: `src_path must be absolute; got "${src_path}".`,
          })
        }
        if (!existsSync(src_path)) {
          return errorJson({
            error: "source_missing",
            message: `Source ELF does not exist: ${src_path}.`,
          })
        }
        if (dst_path !== undefined && !isAbsolute(dst_path)) {
          return errorJson({
            error: "dst_not_absolute",
            message: `dst_path must be absolute when supplied; got "${dst_path}".`,
          })
        }
        if (interpreter !== undefined && !isAbsolute(interpreter)) {
          return errorJson({
            error: "interpreter_not_absolute",
            message: `interpreter must be absolute when supplied; got "${interpreter}".`,
          })
        }
        if (replacements !== undefined) {
          for (const [soname, absPath] of Object.entries(replacements)) {
            if (!isAbsolute(absPath)) {
              return errorJson({
                error: "replacement_not_absolute",
                message: `replacements["${soname}"] must be absolute; got "${absPath}".`,
              })
            }
          }
        }

        const hasInterp = interpreter !== undefined && interpreter !== ""
        const hasReplacements =
          replacements !== undefined && Object.keys(replacements).length > 0
        if (!hasInterp && !hasReplacements) {
          return errorJson({
            error: "nothing_to_patch",
            message:
              "Neither interpreter nor replacements supplied. Use omp_setup_extract_file " +
              "for pure copy operations.",
          })
        }

        // ── delegate to library ───────────────────────────────────────
        try {
          const result = patchElf(
            {
              srcPath: src_path,
              dstPath: dst_path,
              interpreter,
              replacements,
            },
            { spawn: options.spawn },
          )
          return JSON.stringify({
            ok: true,
            patched_path: result.patchedPath,
            original_sha256: result.originalSha256,
            patched_sha256: result.patchedSha256,
            invoked_patchelf: result.invokedPatchelf,
          })
        } catch (err) {
          if (err instanceof EnvSetupError) {
            return errorJson({
              error: err.kind,
              message: err.message,
              detail: err.detail,
            })
          }
          throw err
        }
      } catch (err) {
        return errorJson({
          error: "internal_error",
          message: String(err),
        })
      }
    },
  })
}

function errorJson(payload: {
  error: string
  message: string
  detail?: unknown
}): string {
  return JSON.stringify({ ok: false, ...payload })
}
