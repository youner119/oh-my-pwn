/**
 * omp_stage_challenge — copy challenge files into the canonical workspace mount.
 *
 * D-1 design: pwno-mcp container mounts a FIXED host path (<plugin-root>/workspace)
 * as /workspace. To make a challenge's binary/libc/ld visible to GDB inside the
 * container, this tool copies them from the challenge directory to
 * <workspace>/<challenge_id>/.
 *
 * Idempotent by mtime+size — calling again on unchanged files is cheap (skip).
 * Modified source files trigger a replace ("updated"). Missing sources are
 * surfaced in the per-file response without aborting the whole staging.
 */

import { copyFile, mkdir, stat, utimes } from "node:fs/promises"
import { existsSync } from "node:fs"
import { basename, isAbsolute, resolve } from "node:path"
import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"

export interface StageChallengeToolOptions {
  /** Absolute host path to the canonical workspace mount source. */
  workspacePath: string
}

const CONTAINER_WORKSPACE = "/workspace"

type StagedAction = "copied" | "updated" | "skipped" | "missing"

interface StagedEntry {
  name: string
  host_path: string
  container_path: string
  size: number
  action: StagedAction
  error?: string
}

export function createOmpStageChallengeTool(
  options: StageChallengeToolOptions,
): ToolDefinition {
  return tool({
    description: `Stage challenge files into the canonical workspace mount so the pwno-mcp container can read them.

OmP's workspace is fixed at <plugin-root>/workspace/ (mounted as /workspace inside the container). This tool copies binary + libc + ld (and any other files you list) from a challenge directory to <workspace>/<challenge_id>/, idempotently — size+mtime comparison skips unchanged files, replaces modified ones.

Call this once at Phase 2 entry, AFTER omp_pwno_status reports healthy. Pass the returned container_path values to StrategyAgent (NOT host paths — sub-agents talk to pwno-mcp inside the container).

Per-file action values:
  - "copied":  file did not exist in workspace; freshly copied
  - "updated": file existed with different size/mtime; overwritten
  - "skipped": file unchanged since last staging; left alone
  - "missing": source file does not exist; staging continued for the rest

Returns:
  {
    ok: bool,
    challenge_id: string,
    host_dir: string,
    container_dir: string,            // "/workspace/<id>" — give this to sub-agents
    staged: [
      { name, host_path, container_path, size, action, error? },
      ...
    ]
  }`,
    args: {
      challenge_dir: tool.schema
        .string()
        .describe(
          "Absolute host path to the challenge directory (e.g. /path/to/afterimage).",
        ),
      files: tool.schema
        .array(tool.schema.string())
        .describe(
          "Files to stage, as paths relative to challenge_dir " +
            "(e.g. ['chal', 'libc.so.6', 'ld-linux-x86-64.so.2']). " +
            "Typically derived from state.json: basename(binary_path), basename(libc_path), basename(ld_path).",
        ),
      challenge_id: tool.schema
        .string()
        .optional()
        .describe(
          "Subdirectory name under <workspace>/. Defaults to basename(challenge_dir).",
        ),
    },
    execute: async ({ challenge_dir, files, challenge_id }) => {
      try {
        if (!isAbsolute(challenge_dir)) {
          return JSON.stringify({
            ok: false,
            error: "challenge_dir_not_absolute",
            message: `challenge_dir must be an absolute path; got "${challenge_dir}".`,
          })
        }
        if (!existsSync(challenge_dir)) {
          return JSON.stringify({
            ok: false,
            error: "challenge_dir_missing",
            message: `challenge_dir does not exist: ${challenge_dir}`,
          })
        }

        const id = challenge_id ?? basename(challenge_dir)
        if (!id || id === "." || id === "..") {
          return JSON.stringify({
            ok: false,
            error: "invalid_challenge_id",
            message: `challenge_id resolved to "${id}". Pass an explicit challenge_id.`,
          })
        }

        const targetDir = resolve(options.workspacePath, id)
        await mkdir(targetDir, { recursive: true })

        const staged: StagedEntry[] = []
        for (const rel of files) {
          const srcPath = resolve(challenge_dir, rel)
          const fileName = basename(rel)
          const destPath = resolve(targetDir, fileName)
          const containerPath = `${CONTAINER_WORKSPACE}/${id}/${fileName}`

          if (!existsSync(srcPath)) {
            staged.push({
              name: fileName,
              host_path: srcPath,
              container_path: containerPath,
              size: 0,
              action: "missing",
              error: `source file does not exist: ${srcPath}`,
            })
            continue
          }

          try {
            const srcStat = await stat(srcPath)
            let action: StagedAction = "copied"

            if (existsSync(destPath)) {
              const destStat = await stat(destPath)
              const mtimeMatches =
                Math.abs(destStat.mtimeMs - srcStat.mtimeMs) < 1
              if (destStat.size === srcStat.size && mtimeMatches) {
                staged.push({
                  name: fileName,
                  host_path: srcPath,
                  container_path: containerPath,
                  size: srcStat.size,
                  action: "skipped",
                })
                continue
              }
              action = "updated"
            }

            await copyFile(srcPath, destPath)
            // Preserve mtime so future stages are idempotent.
            await utimes(destPath, srcStat.atime, srcStat.mtime)

            staged.push({
              name: fileName,
              host_path: srcPath,
              container_path: containerPath,
              size: srcStat.size,
              action,
            })
          } catch (copyErr) {
            staged.push({
              name: fileName,
              host_path: srcPath,
              container_path: containerPath,
              size: 0,
              action: "missing",
              error: String(copyErr),
            })
          }
        }

        return JSON.stringify({
          ok: true,
          challenge_id: id,
          host_dir: targetDir,
          container_dir: `${CONTAINER_WORKSPACE}/${id}`,
          staged,
        })
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
