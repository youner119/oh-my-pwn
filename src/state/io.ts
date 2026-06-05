/**
 * Filesystem I/O for the per-challenge OmP state directory.
 *
 * Responsibilities:
 *
 * - {@link initializeOmpDir}   — create `.omp/` + standard subdirs +
 *                                 an empty `journal.md`. Idempotent: safe
 *                                 to call on an existing challenge (never
 *                                 overwrites the journal).
 * - {@link saveChallengeState} — atomic write via tmp-file + rename, bumps
 *                                 `updated_at`, re-validates before writing.
 *
 * No async APIs: OmO's hook tiers and plugin lifecycle are sync-friendly and
 * the boulder-state reference module in the same repo uses sync `node:fs`.
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs"
import { dirname } from "node:path"
import {
  ChallengeStateSchema,
  VulnCandidateSchema,
  type ChallengeState,
  type VulnCandidate,
} from "./challenge-state"
import {
  resolveOmpDir,
  resolveStatePath,
  resolveJournalPath,
  resolveCandidatePath,
  resolveCandidatesDir,
  OMP_SUBDIRS,
} from "./layout"
import { initializeJournal } from "./journal"

/** Thrown when `state.json` exists but cannot be parsed/validated. */
export class ChallengeStateLoadError extends Error {
  constructor(
    message: string,
    public readonly statePath: string,
    public readonly cause?: unknown,
  ) {
    super(message)
    this.name = "ChallengeStateLoadError"
  }
}

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

/**
 * Persist a `ChallengeState` atomically.
 *
 * Stamps `updated_at` to `now`, re-validates via Zod (defensive — catches
 * callers that hand-mutated the object past what the schema allows), then
 * writes via a tmp-file + `rename` so partial writes cannot corrupt
 * `state.json`.
 */
export function saveChallengeState(
  state: ChallengeState,
  now: Date = new Date(),
): ChallengeState {
  const stamped: ChallengeState = {
    ...state,
    updated_at: now.toISOString(),
  }
  const validated = ChallengeStateSchema.parse(stamped)
  const statePath = resolveStatePath(validated.challenge_dir)
  ensureDir(dirname(statePath))
  writeJsonAtomic(statePath, validated)
  return validated
}

/**
 * Atomic single-line JSON write. tmp + rename — readers never see partial
 * writes; rename is atomic on POSIX same-filesystem. Minified (no indent)
 * because OmP's state files grow past opencode's line-based tool output cap
 * when an agent reads them directly. One-line JSON keeps the read result
 * intact. For human inspection use `jq .`.
 */
function writeJsonAtomic(path: string, value: unknown): void {
  const tmpPath = `${path}.tmp`
  writeFileSync(tmpPath, `${JSON.stringify(value)}\n`, "utf-8")
  renameSync(tmpPath, path)
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

/* ── Per-candidate detail files (spec: state-split-vuln-candidates.md) ───── */

/** Thrown when a candidate file exists but cannot be parsed/validated. */
export class CandidateLoadError extends Error {
  constructor(
    message: string,
    public readonly candidatePath: string,
    public readonly cause?: unknown,
  ) {
    super(message)
    this.name = "CandidateLoadError"
  }
}

/**
 * Candidate id charset — alphanumeric + underscore + dash. Tight so the id
 * maps directly to a filesystem-safe filename (no escape needed).
 */
const CANDIDATE_ID_PATTERN = /^[A-Za-z0-9_-]+$/

function validateCandidateId(id: string): void {
  if (!CANDIDATE_ID_PATTERN.test(id)) {
    throw new Error(
      `Invalid candidate id: ${JSON.stringify(id)} (allowed: alphanumeric + _ + -)`,
    )
  }
}

/**
 * Read `<challengeDir>/.omp/candidates/<id>.json`. Returns `null` when the
 * file is missing; throws {@link CandidateLoadError} on parse / schema
 * failure so the Orchestrator fails loud.
 */
export function loadCandidate(
  challengeDir: string,
  id: string,
): VulnCandidate | null {
  validateCandidateId(id)
  const path = resolveCandidatePath(challengeDir, id)
  if (!existsSync(path)) return null
  let raw: string
  try {
    raw = readFileSync(path, "utf-8")
  } catch (err) {
    throw new CandidateLoadError(
      `Failed to read candidate file: ${String(err)}`,
      path,
      err,
    )
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (err) {
    throw new CandidateLoadError(
      `Candidate file is not valid JSON: ${String(err)}`,
      path,
      err,
    )
  }
  const result = VulnCandidateSchema.safeParse(parsed)
  if (!result.success) {
    throw new CandidateLoadError(
      `Candidate file failed schema validation: ${result.error.message}`,
      path,
      result.error,
    )
  }
  return result.data
}

/**
 * Validate + atomic write `<challengeDir>/.omp/candidates/<id>.json`.
 * Returns the validated candidate (schema may strip unknown fields). The
 * `id` field of `candidate` must match the `id` argument.
 */
export function saveCandidate(
  challengeDir: string,
  id: string,
  candidate: VulnCandidate,
): VulnCandidate {
  validateCandidateId(id)
  if (candidate.id !== id) {
    throw new Error(
      `saveCandidate id mismatch: arg=${JSON.stringify(id)} candidate.id=${JSON.stringify(candidate.id)}`,
    )
  }
  const validated = VulnCandidateSchema.parse(candidate)
  ensureDir(resolveCandidatesDir(challengeDir))
  const path = resolveCandidatePath(challengeDir, id)
  writeJsonAtomic(path, validated)
  return validated
}

/**
 * Remove `<challengeDir>/.omp/candidates/<id>.json`. Returns `true` if the
 * file existed and was deleted, `false` if the file was already absent.
 */
export function deleteCandidate(challengeDir: string, id: string): boolean {
  validateCandidateId(id)
  const path = resolveCandidatePath(challengeDir, id)
  if (!existsSync(path)) return false
  unlinkSync(path)
  return true
}
