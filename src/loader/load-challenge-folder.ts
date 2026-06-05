/**
 * `omp_load_challenge` — challenge folder bootstrapper.
 *
 * Single entry point: {@link loadChallengeFolder}. Given an absolute (or
 * relative) path to a CTF challenge folder, this function:
 *
 *   1. Validates that the path exists and is a directory.
 *   2. Bootstraps `<challenge-dir>/.omp/{journal.md, exploit/, logs/,
 *      artifacts/, candidates/}` via {@link initializeOmpDir}, which is
 *      itself idempotent. State now lives in the db-mcp SQLite store, so the
 *      loader no longer seeds `state.json`.
 *   3. Optionally returns `workspace_root` (the plugin's host workspace
 *      mount source) so downstream agents can derive per-challenge container
 *      paths without inferring the plugin root.
 *
 * That is the entire job. **Binary / Dockerfile / source detection is the
 * omp-setup agent's responsibility** (Phase 0 — Detect), per
 * `.omc/specs/contract-load-detect-split.md` (D1, D2). The loader no longer
 * scans for ELF binaries, validates Dockerfile presence, computes SHA, or
 * tracks input-identity drift. A folder with no binary and no Dockerfile is
 * a valid input — `omp-setup` Phase 0 will classify it as
 * `challenge_type === "unsupported"` and the Orchestrator will dispatch
 * Mode 0/9 from there.
 */

import { existsSync, statSync } from "node:fs"
import { resolve } from "node:path"
import { initializeOmpDir, getStatePaths } from "../state/io"
import { appendJournalSection } from "../state/journal"
import { ChallengeLoadError } from "./challenge-load-error"

export interface LoadChallengeFolderOptions {
  /**
   * Absolute host path to the plugin's workspace mount source
   * (`<plugin-root>/workspace/`). When supplied, seeded into
   * `state.workspace_root` so downstream agents (Setup, Reverser, VH, SA,
   * Exploiter) can derive per-challenge container paths without inferring
   * the plugin root themselves. Plugin.ts wires `OMP_WORKSPACE_PATH` here.
   */
  workspaceRoot?: string
}

export interface LoadChallengeFolderResult {
  /**
   * The plugin's host workspace mount source, echoed back from
   * `opts.workspaceRoot` when supplied. Undefined when not provided.
   */
  workspace_root?: string
  /**
   * True if `journal.md` did not exist before this call (i.e. the loader
   * just bootstrapped a new challenge). False on reload.
   */
  freshlyInitialized: boolean
}

/**
 * Validate `<challengeDir>` exists and bootstrap (or reload) its `.omp/`
 * state directory. See module doc for the full contract.
 *
 * @throws ChallengeLoadError when the path does not exist or is not a
 *         directory.
 */
export function loadChallengeFolder(
  challengeDirInput: string,
  opts: LoadChallengeFolderOptions = {},
  now: Date = new Date(),
): LoadChallengeFolderResult {
  const challengeDir = resolve(challengeDirInput)

  if (!existsSync(challengeDir)) {
    throw new ChallengeLoadError({
      kind: "missing-dir",
      challengeDir,
      message: `Challenge directory not found: ${challengeDir}`,
    })
  }
  if (!statSync(challengeDir).isDirectory()) {
    throw new ChallengeLoadError({
      kind: "not-a-directory",
      challengeDir,
      message: `Path is not a directory: ${challengeDir}`,
    })
  }

  const { journalPath } = getStatePaths(challengeDir)
  const freshlyInitialized = !existsSync(journalPath)

  initializeOmpDir(challengeDir, now)

  if (freshlyInitialized) {
    appendJournalSection(
      challengeDir,
      "challenge loaded",
      buildLoadedJournalBody({ challengeDir }),
      now,
    )
  }

  return {
    ...(opts.workspaceRoot !== undefined
      ? { workspace_root: opts.workspaceRoot }
      : {}),
    freshlyInitialized,
  }
}

interface LoadedBody {
  challengeDir: string
}

function buildLoadedJournalBody(input: LoadedBody): string {
  return [
    `- challenge_dir: \`${input.challengeDir}\``,
    "- next: invoke omp-setup agent (Phase 0 Detect populates binary / dockerfile / source fields).",
  ].join("\n")
}
