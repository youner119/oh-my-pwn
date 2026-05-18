/**
 * omp_setup_extract_file — Phase 3 / Phase 5 of omp-setup agent.
 *
 * Single-file copy with two source kinds:
 *
 *   - source="image": `docker create <image>` + `docker cp <container>:<src>
 *                     <dest>` + `docker rm -f <container>`. Used in Phase 3
 *                     to extract NEEDED libraries + ld-linux from a built
 *                     image into `.omp/artifacts/`.
 *
 *   - source="host":  plain host-to-host file copy via fs.copyFile. Used in
 *                     Phase 5 to copy `.omp/artifacts/<lib>` into
 *                     `workspace/<challenge_id>/<lib>` for pwno-mcp.
 *
 * Each call is self-contained — the `docker create`/`docker rm` lifecycle
 * is not shared across calls. For a workload of N libraries that costs ~N
 * × (create+rm), which is ≈50–100ms × N, acceptable for setup-phase. A
 * future optimisation could batch via a container-pool tool, but T06 keeps
 * the surface atomic.
 *
 * Symlink policy:
 *   - dereference_symlinks: true  (default) — `docker cp -L` / fs.copyFile
 *     (which follows symlinks). Self-contained file at dest.
 *   - dereference_symlinks: false — preserve the symlink itself. For host
 *     source, the symlink target is read with readlink and re-created at
 *     dest. For image source, `docker cp` (without -L) preserves the
 *     symlink; the caller is then responsible for extracting the target
 *     file separately.
 */

import { existsSync, statSync } from "node:fs"
import {
  copyFile,
  lstat,
  mkdir,
  readFile,
  readlink,
  symlink,
  unlink,
} from "node:fs/promises"
import { createHash } from "node:crypto"
import { dirname, isAbsolute } from "node:path"
import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import {
  realDockerRunner,
  type DockerRunner,
} from "../envsetup/docker-runner"

export interface OmpSetupExtractFileToolOptions {
  /** Inject a fake docker runner for tests (image source). */
  runner?: DockerRunner
}

export function createOmpSetupExtractFileTool(
  options: OmpSetupExtractFileToolOptions = {},
): ToolDefinition {
  const runner = options.runner ?? realDockerRunner

  return tool({
    description:
      "Copy a single file from one of two source kinds to a destination on the " +
      "host. Used in Phase 3 (extract NEEDED libs from Docker image into " +
      ".omp/artifacts/) and Phase 5 (stage to workspace/<id>/ for pwno-mcp). " +
      "Parent of dest_path is created automatically. Returns " +
      "{ ok, dest_path, sha256, size } on success or a typed error " +
      "(invalid_source, image_tag_required, src_not_absolute, dest_not_absolute, " +
      "source_missing, docker-not-available, docker-create-failed, docker-cp-failed, " +
      "host_copy_failed, dest_missing_after_copy, internal_error).",
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
            '(e.g. /lib/x86_64-linux-gnu/libc.so.6). For source="host" this is an absolute host path.',
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
          "If true (default), follow symlinks and copy the realfile. " +
            'If false, preserve the symlink itself; the caller is responsible ' +
            'for extracting symlink targets separately.',
        ),
    },
    execute: async ({
      source,
      image_tag,
      src_path,
      dest_path,
      dereference_symlinks,
    }) => {
      try {
        // ── validation ────────────────────────────────────────────────
        if (source !== "image" && source !== "host") {
          return errorJson({
            error: "invalid_source",
            message: `source must be "image" or "host"; got "${String(source)}".`,
          })
        }
        if (!isAbsolute(dest_path)) {
          return errorJson({
            error: "dest_not_absolute",
            message: `dest_path must be absolute; got "${dest_path}".`,
          })
        }
        if (!isAbsolute(src_path)) {
          return errorJson({
            error: "src_not_absolute",
            message: `src_path must be absolute; got "${src_path}".`,
          })
        }

        const deref = dereference_symlinks !== false  // default true

        await mkdir(dirname(dest_path), { recursive: true })

        if (source === "image") {
          if (image_tag === undefined || image_tag === "") {
            return errorJson({
              error: "image_tag_required",
              message: 'image_tag is required when source="image".',
            })
          }
          return await extractFromImage(
            image_tag,
            src_path,
            dest_path,
            deref,
            runner,
          )
        }

        // source === "host"
        return await extractFromHost(src_path, dest_path, deref)
      } catch (err) {
        return errorJson({
          error: "internal_error",
          message: String(err),
        })
      }
    },
  })
}

/* ── image source ─────────────────────────────────────────────────────── */

async function extractFromImage(
  imageTag: string,
  srcPath: string,
  destPath: string,
  dereference: boolean,
  runner: DockerRunner,
): Promise<string> {
  let containerId: string
  try {
    const createRes = runner.run(["create", imageTag])
    if (createRes.exitCode !== 0) {
      return errorJson({
        error: "docker-create-failed",
        message: `docker create ${imageTag} failed (exit ${createRes.exitCode}).`,
        detail: {
          exit_code: createRes.exitCode,
          stderr: createRes.stderr.toString("utf-8").slice(0, 2048),
        },
      })
    }
    containerId = createRes.stdout.toString("utf-8").trim()
    if (containerId === "") {
      return errorJson({
        error: "docker-create-failed",
        message: `docker create ${imageTag} returned empty container id.`,
      })
    }
  } catch (err) {
    return translateSpawnError(err)
  }

  try {
    const cpArgs = ["cp"]
    if (dereference) {
      cpArgs.push("-L")
    }
    cpArgs.push(`${containerId}:${srcPath}`, destPath)

    let cpRes
    try {
      cpRes = runner.run(cpArgs)
    } catch (err) {
      return translateSpawnError(err)
    }
    if (cpRes.exitCode !== 0) {
      const stderr = cpRes.stderr.toString("utf-8").slice(0, 2048)
      // Distinguish "source not found in image" from other failures.
      const errorKind = /(?:No such file|not found|does not exist)/iu.test(stderr)
        ? "source_missing"
        : "docker-cp-failed"
      return errorJson({
        error: errorKind,
        message: `docker cp ${imageTag}:${srcPath} → ${destPath} failed (exit ${cpRes.exitCode}).`,
        detail: { exit_code: cpRes.exitCode, stderr },
      })
    }

    return await finalizeDestResult(destPath)
  } finally {
    // Best effort cleanup — never throw out of finally.
    try {
      runner.run(["rm", "-f", containerId])
    } catch {
      // intentionally ignored
    }
  }
}

/* ── host source ──────────────────────────────────────────────────────── */

async function extractFromHost(
  srcPath: string,
  destPath: string,
  dereference: boolean,
): Promise<string> {
  if (!existsSync(srcPath)) {
    return errorJson({
      error: "source_missing",
      message: `Source path does not exist: ${srcPath}.`,
    })
  }

  try {
    if (existsSync(destPath)) {
      await unlink(destPath)
    }
    if (dereference) {
      await copyFile(srcPath, destPath)
    } else {
      const lst = await lstat(srcPath)
      if (lst.isSymbolicLink()) {
        const target = await readlink(srcPath)
        await symlink(target, destPath)
      } else {
        await copyFile(srcPath, destPath)
      }
    }
  } catch (err) {
    return errorJson({
      error: "host_copy_failed",
      message: `Failed to copy ${srcPath} → ${destPath}: ${String(err)}`,
    })
  }

  return await finalizeDestResult(destPath)
}

/* ── helpers ──────────────────────────────────────────────────────────── */

async function finalizeDestResult(destPath: string): Promise<string> {
  if (!existsSync(destPath)) {
    return errorJson({
      error: "dest_missing_after_copy",
      message: `Copy reported success but ${destPath} does not exist on disk.`,
    })
  }
  // Use statSync (dereferences) so symlink dests return target size; the
  // sha256 is also of the target's content for symlinks (consistent with
  // what ld would actually load).
  let size: number
  try {
    size = statSync(destPath).size
  } catch {
    size = 0
  }

  let sha256 = ""
  try {
    const bytes = await readFile(destPath)
    sha256 = createHash("sha256").update(bytes).digest("hex")
  } catch {
    // sha computation failure is non-fatal — we still report success.
  }

  return JSON.stringify({
    ok: true,
    dest_path: destPath,
    sha256,
    size,
  })
}

function errorJson(payload: {
  error: string
  message: string
  detail?: unknown
}): string {
  return JSON.stringify({ ok: false, ...payload })
}

function translateSpawnError(err: unknown): string {
  const code = (err as NodeJS.ErrnoException | undefined)?.code
  return errorJson({
    error: "docker-not-available",
    message:
      code === "ENOENT"
        ? "docker binary not found in PATH. Install docker and retry."
        : `Failed to spawn docker: ${(err as Error).message}`,
  })
}
