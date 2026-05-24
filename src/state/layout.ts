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
  CANDIDATES_DIR,
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

/** Absolute path to `<challengeDir>/.omp/candidates/`. */
export function resolveCandidatesDir(challengeDir: string): string {
  return join(resolveOmpDir(challengeDir), CANDIDATES_DIR)
}

/**
 * Absolute path to `<challengeDir>/.omp/candidates/<id>.json`. `id` 검증은
 * 호출자 책임 — io 의 candidate read/write 가 사용 전에 validateCandidateId 박음.
 */
export function resolveCandidatePath(challengeDir: string, id: string): string {
  return join(resolveCandidatesDir(challengeDir), `${id}.json`)
}

/**
 * All standard subdirectories OmP expects to exist under `.omp/`.
 * Used by {@link import("./io").initializeOmpDir} to seed the layout.
 */
export const OMP_SUBDIRS: readonly string[] = [
  EXPLOIT_DIR,
  LOGS_DIR,
  ARTIFACTS_DIR,
  CANDIDATES_DIR,
]
