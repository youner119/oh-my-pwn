/**
 * Path helpers for the per-challenge `.omp/` directory.
 *
 * A challenge folder is identified purely by its absolute filesystem path; no
 * slug is stored or computed. These helpers are intentionally pure string
 * manipulation — no filesystem access, no side effects — so they can be called
 * freely from hot paths and tests.
 */

import { join } from "node:path"
import {
  OMP_DIR,
  STATE_FILE,
  JOURNAL_FILE,
  EXPLOIT_DIR,
  LOGS_DIR,
  ARTIFACTS_DIR,
} from "./constants"

/** Absolute path to `<challengeDir>/.omp/`. */
export function resolveOmpDir(challengeDir: string): string {
  return join(challengeDir, OMP_DIR)
}

/** Absolute path to `<challengeDir>/.omp/state.json`. */
export function resolveStatePath(challengeDir: string): string {
  return join(resolveOmpDir(challengeDir), STATE_FILE)
}

/** Absolute path to `<challengeDir>/.omp/journal.md`. */
export function resolveJournalPath(challengeDir: string): string {
  return join(resolveOmpDir(challengeDir), JOURNAL_FILE)
}

/** Absolute path to `<challengeDir>/.omp/exploit/`. */
export function resolveExploitDir(challengeDir: string): string {
  return join(resolveOmpDir(challengeDir), EXPLOIT_DIR)
}

/** Absolute path to `<challengeDir>/.omp/logs/`. */
export function resolveLogsDir(challengeDir: string): string {
  return join(resolveOmpDir(challengeDir), LOGS_DIR)
}

/** Absolute path to `<challengeDir>/.omp/artifacts/`. */
export function resolveArtifactsDir(challengeDir: string): string {
  return join(resolveOmpDir(challengeDir), ARTIFACTS_DIR)
}

/**
 * All standard subdirectories OmP expects to exist under `.omp/`.
 * Used by {@link import("./io").initializeOmpDir} to seed the layout.
 */
export const OMP_SUBDIRS: readonly string[] = [
  EXPLOIT_DIR,
  LOGS_DIR,
  ARTIFACTS_DIR,
]
