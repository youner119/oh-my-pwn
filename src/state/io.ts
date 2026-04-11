/**
 * Filesystem I/O for the per-challenge OmP state directory.
 *
 * Three responsibilities:
 *
 * - {@link initializeOmpDir}   — create `.omp/` + standard subdirs + seed
 *                                 `state.json` and an empty `journal.md`.
 *                                 Idempotent: safe to call on an existing
 *                                 challenge (never overwrites).
 * - {@link loadChallengeState} — read `state.json`, Zod-validate, return
 *                                 typed state. Returns `null` on missing
 *                                 file; throws on malformed JSON / schema
 *                                 violations so the Orchestrator fails loud
 *                                 instead of silently running on stale state.
 * - {@link saveChallengeState} — atomic write via tmp-file + rename, bumps
 *                                 `updated_at`, re-validates before writing.
 *
 * No async APIs: OmO's hook tiers and plugin lifecycle are sync-friendly and
 * the boulder-state reference module in the same repo uses sync `node:fs`.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs"
import { dirname } from "node:path"
import {
  ChallengeStateSchema,
  createInitialChallengeState,
  type ChallengeState,
  type InitialChallengeStateInput,
} from "./challenge-state"
import {
  resolveOmpDir,
  resolveStatePath,
  resolveJournalPath,
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
 * - Creates `.omp/`, `exploit/`, `logs/`, `artifacts/` if missing.
 * - If `state.json` is missing, writes an initial ChallengeState derived
 *   from `input`.
 * - If `journal.md` is missing, writes an initial header.
 *
 * Idempotent in the success path: calling it again on an already-initialized
 * challenge returns the previously persisted ChallengeState without touching
 * any existing file. **Throws** {@link ChallengeStateLoadError} if
 * `state.json` exists but is corrupt or fails schema validation — on purpose,
 * so callers cannot silently overwrite in-progress exploitation state.
 */
export function initializeOmpDir(
  input: InitialChallengeStateInput,
  now: Date = new Date(),
): ChallengeState {
  const ompDir = resolveOmpDir(input.challenge_dir)
  ensureDir(ompDir)
  for (const sub of OMP_SUBDIRS) {
    ensureDir(`${ompDir}/${sub}`)
  }

  const statePath = resolveStatePath(input.challenge_dir)
  let state: ChallengeState
  if (existsSync(statePath)) {
    const loaded = loadChallengeState(input.challenge_dir)
    if (!loaded) {
      // existsSync said yes but loader said no → filesystem race; treat as fresh.
      state = createInitialChallengeState(input, now)
      writeStateFileAtomic(statePath, state)
    } else {
      state = loaded
    }
  } else {
    state = createInitialChallengeState(input, now)
    writeStateFileAtomic(statePath, state)
  }

  initializeJournal(input.challenge_dir, state, now)

  return state
}

/**
 * Read and Zod-validate `state.json` inside a challenge folder.
 *
 * - Returns `null` when the file does not exist (fresh challenge).
 * - Throws {@link ChallengeStateLoadError} on malformed JSON or schema
 *   violation — callers should surface this; it indicates either manual
 *   corruption or a schema version drift needing migration.
 */
export function loadChallengeState(challengeDir: string): ChallengeState | null {
  const statePath = resolveStatePath(challengeDir)
  if (!existsSync(statePath)) {
    return null
  }

  let raw: string
  try {
    raw = readFileSync(statePath, "utf-8")
  } catch (cause) {
    throw new ChallengeStateLoadError(
      `Failed to read ${statePath}`,
      statePath,
      cause,
    )
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (cause) {
    throw new ChallengeStateLoadError(
      `${statePath} is not valid JSON`,
      statePath,
      cause,
    )
  }

  const result = ChallengeStateSchema.safeParse(parsed)
  if (!result.success) {
    throw new ChallengeStateLoadError(
      `${statePath} failed ChallengeState schema validation: ${result.error.message}`,
      statePath,
      result.error,
    )
  }
  return result.data
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
  writeStateFileAtomic(statePath, validated)
  return validated
}

function writeStateFileAtomic(statePath: string, state: ChallengeState): void {
  const tmpPath = `${statePath}.tmp`
  writeFileSync(tmpPath, `${JSON.stringify(state, null, 2)}\n`, "utf-8")
  renameSync(tmpPath, statePath)
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
