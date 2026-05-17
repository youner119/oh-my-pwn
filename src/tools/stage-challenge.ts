/**
 * omp_stage_challenge — copy challenge files into the canonical workspace mount.
 *
 * pwno 호환성 수정 design: pwno-mcp container mounts a FIXED host path (<plugin-root>/workspace)
 * as /workspace. To make a challenge's binary/libc/ld visible to GDB inside the
 * container, this tool copies them from the challenge directory to
 * <workspace>/<challenge_id>/.
 *
 * Source selection: for each requested file, if a backup copy exists at
 * `<challenge_dir>/.omp/artifacts/<basename>.orig` (created by envsetup's
 * patch-elf step), it is preferred over the live file. This avoids carrying
 * envsetup's host-only patchelf interpreter into the container.
 *
 * Optional patchelf rewrite: when `binary_name`, `libc_name`, and `ld_name`
 * are all supplied AND all three files staged successfully, the staged
 * binary's interpreter/rpath is rewritten to container paths
 * (`/workspace/<id>/<ld>` + `/workspace/<id>`). The result enables a plain
 * `process(BIN)` call from inside Mode 2/4.
 *
 * Idempotent by mtime+size — calling again on unchanged files is cheap (skip).
 * Modified source files trigger a replace ("updated"). Missing sources are
 * surfaced in the per-file response without aborting the whole staging.
 */

import { copyFile, mkdir, stat, utimes, unlink } from "node:fs/promises"
import { existsSync } from "node:fs"
import { basename, isAbsolute, resolve } from "node:path"
import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import { patchBinaryInterpreter, type SpawnFn } from "../envsetup"

export interface StageChallengeToolOptions {
  /** Absolute host path to the canonical workspace mount source. */
  workspacePath: string
  /** Inject a fake patchelf spawn for tests. */
  patchelfSpawn?: SpawnFn
}

const CONTAINER_WORKSPACE = "/workspace"
const ORIG_DIR_REL = ".omp/artifacts"
const HOST_BACKUP_DIR = ".host-orig"

type StagedAction = "copied" | "updated" | "skipped" | "missing"

interface StagedEntry {
  name: string
  host_path: string
  source_kind: "orig_backup" | "live"
  container_path: string
  size: number
  action: StagedAction
  error?: string
}

interface PatchelfResponse {
  applied: boolean
  reason?: string
  binary_host_path?: string
  backup_host_path?: string
  interpreter_set?: string
  rpath_set?: string
  original_sha256?: string
  patched_sha256?: string
}

export function createOmpStageChallengeTool(
  options: StageChallengeToolOptions,
): ToolDefinition {
  return tool({
    description: `Stage challenge files into the canonical workspace mount so the pwno-mcp container can read them.

OmP's workspace is fixed at <plugin-root>/workspace/ (mounted as /workspace inside the container). This tool copies binary + libc + ld (and any other files you list) from a challenge directory to <workspace>/<challenge_id>/, idempotently — size+mtime comparison skips unchanged files, replaces modified ones.

Source selection: for each file, if <challenge_dir>/.omp/artifacts/<basename>.orig exists (created by envsetup's patchelf step as a backup of the original binary), it is preferred. Otherwise the live file at <challenge_dir>/<rel> is used.

Patchelf rewrite (recommended): pass binary_name + libc_name + ld_name to have the staged binary's interpreter/rpath rewritten to container paths (/workspace/<id>/<ld> and /workspace/<id>). After this, inside Mode 2/4 you can call \`process(BIN)\` / \`pwno_set_file\` / \`pwno_pwncli\` with binary_path=/workspace/<id>/<binary> directly — no LD --library-path dance needed.

Call this once at Phase 2 entry, AFTER omp_pwno_status reports healthy. Pass the returned container_path values to StrategyAgent.

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
      { name, host_path, source_kind, container_path, size, action, error? },
      ...
    ],
    patchelf: {
      applied: bool,
      reason?: string,                // skipped-args | source-missing | failed
      binary_host_path?, backup_host_path?,
      interpreter_set?, rpath_set?,
      original_sha256?, patched_sha256?
    }
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
      binary_name: tool.schema
        .string()
        .optional()
        .describe(
          "Basename of the binary inside `files`. Required to trigger patchelf rewrite.",
        ),
      libc_name: tool.schema
        .string()
        .optional()
        .describe(
          "Basename of libc inside `files`. Required to trigger patchelf rewrite.",
        ),
      ld_name: tool.schema
        .string()
        .optional()
        .describe(
          "Basename of ld interpreter inside `files`. Required to trigger patchelf rewrite (becomes the new --set-interpreter).",
        ),
    },
    execute: async ({
      challenge_dir,
      files,
      challenge_id,
      binary_name,
      libc_name,
      ld_name,
    }) => {
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
          const fileName = basename(rel)
          const liveSrc = resolve(challenge_dir, rel)
          const origSrc = resolve(
            challenge_dir,
            ORIG_DIR_REL,
            `${fileName}.orig`,
          )
          const useOrig = existsSync(origSrc)
          const srcPath = useOrig ? origSrc : liveSrc
          const sourceKind: StagedEntry["source_kind"] = useOrig
            ? "orig_backup"
            : "live"
          const destPath = resolve(targetDir, fileName)
          const containerPath = `${CONTAINER_WORKSPACE}/${id}/${fileName}`

          if (!existsSync(srcPath)) {
            staged.push({
              name: fileName,
              host_path: srcPath,
              source_kind: sourceKind,
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
                  source_kind: sourceKind,
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
              source_kind: sourceKind,
              container_path: containerPath,
              size: srcStat.size,
              action,
            })
          } catch (copyErr) {
            staged.push({
              name: fileName,
              host_path: srcPath,
              source_kind: sourceKind,
              container_path: containerPath,
              size: 0,
              action: "missing",
              error: String(copyErr),
            })
          }
        }

        const patchelf = await maybeApplyPatchelf({
          targetDir,
          challengeDir: challenge_dir,
          challengeId: id,
          staged,
          binaryName: binary_name,
          libcName: libc_name,
          ldName: ld_name,
          spawn: options.patchelfSpawn,
        })

        return JSON.stringify({
          ok: true,
          challenge_id: id,
          host_dir: targetDir,
          container_dir: `${CONTAINER_WORKSPACE}/${id}`,
          staged,
          patchelf,
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

interface PatchelfRequest {
  targetDir: string
  challengeDir: string
  challengeId: string
  staged: StagedEntry[]
  binaryName?: string
  libcName?: string
  ldName?: string
  spawn?: SpawnFn
}

async function maybeApplyPatchelf(
  req: PatchelfRequest,
): Promise<PatchelfResponse> {
  if (!req.binaryName || !req.libcName || !req.ldName) {
    return {
      applied: false,
      reason: "skipped-args: binary_name/libc_name/ld_name not all provided",
    }
  }

  const binEntry = req.staged.find((s) => s.name === req.binaryName)
  const libcEntry = req.staged.find((s) => s.name === req.libcName)
  const ldEntry = req.staged.find((s) => s.name === req.ldName)

  const missing: string[] = []
  if (!binEntry || binEntry.action === "missing")
    missing.push(`binary(${req.binaryName})`)
  if (!libcEntry || libcEntry.action === "missing")
    missing.push(`libc(${req.libcName})`)
  if (!ldEntry || ldEntry.action === "missing")
    missing.push(`ld(${req.ldName})`)
  if (missing.length > 0) {
    return {
      applied: false,
      reason: `source-missing: ${missing.join(", ")} not in staged set`,
    }
  }

  const binaryHost = resolve(req.targetDir, req.binaryName)
  const backupDir = resolve(req.targetDir, HOST_BACKUP_DIR)
  const backupHost = resolve(backupDir, req.binaryName)
  const interpreterContainer = `${CONTAINER_WORKSPACE}/${req.challengeId}/${req.ldName}`
  const libcContainerDir = `${CONTAINER_WORKSPACE}/${req.challengeId}`

  await mkdir(backupDir, { recursive: true })
  // If the staged binary was just (re)written, drop the old backup so
  // patchBinaryInterpreter recreates one from the fresh source.
  if (
    binEntry &&
    (binEntry.action === "copied" || binEntry.action === "updated") &&
    existsSync(backupHost)
  ) {
    await unlink(backupHost)
  }

  try {
    const result = patchBinaryInterpreter(
      {
        binaryPath: binaryHost,
        backupPath: backupHost,
        interpreterPath: interpreterContainer,
        libcDir: libcContainerDir,
        challengeDir: req.challengeDir,
      },
      { spawn: req.spawn },
    )
    return {
      applied: true,
      binary_host_path: binaryHost,
      backup_host_path: backupHost,
      interpreter_set: interpreterContainer,
      rpath_set: libcContainerDir,
      original_sha256: result.originalSha256,
      patched_sha256: result.patchedSha256,
    }
  } catch (err) {
    return {
      applied: false,
      reason: `failed: ${String(err)}`,
    }
  }
}
