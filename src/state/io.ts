/**
 * Filesystem scaffold for the per-challenge OmP `.omp/` directory.
 *
 * Bootstraps the `.omp/` layout and resolves paths within it. State and
 * candidate persistence now live in the db-mcp SQLite store, so this module
 * no longer reads or writes `state.json` / candidate files — only the
 * directory scaffold + `journal.md` (which stays a plain file).
 *
 * No async APIs: OmO's hook tiers and plugin lifecycle are sync-friendly.
 */

import { mkdirSync } from "node:fs"
import {
  resolveOmpDir,
  resolveStatePath,
  resolveJournalPath,
  OMP_SUBDIRS,
} from "./layout"
import { initializeJournal } from "./journal"

function ensureDir(path: string): void {
  // mkdirSync with recursive:true is already idempotent: it does not throw
  // when the directory exists. No existsSync guard needed.
  mkdirSync(path, { recursive: true })
}

/**
 * Seed a fresh `.omp/` layout inside the given challenge folder.
 *
 * - Creates `.omp/`, `exploit/`, `logs/`, `artifacts/`, `candidates/` if
 *   missing.
 * - If `journal.md` is missing, writes an initial header.
 *
 * Idempotent: calling it again on an already-initialized challenge never
 * touches an existing `journal.md`. State persistence now lives in the
 * db-mcp SQLite store, so this no longer seeds `state.json`.
 */
export function initializeOmpDir(
  challengeDir: string,
  now: Date = new Date(),
): void {
  const ompDir = resolveOmpDir(challengeDir)
  ensureDir(ompDir)
  for (const sub of OMP_SUBDIRS) {
    ensureDir(`${ompDir}/${sub}`)
  }

  initializeJournal(challengeDir, now)
}

/** Paths consumers may want without pulling in `layout.ts` directly. */
export function getStatePaths(challengeDir: string): {
  ompDir: string
  statePath: string
  journalPath: string
} {
  return {
    ompDir: resolveOmpDir(challengeDir),
    statePath: resolveStatePath(challengeDir),
    journalPath: resolveJournalPath(challengeDir),
  }
}
