/**
 * Zod schema for the persistent per-challenge state file (`state.json`).
 *
 * `ChallengeState` is the single machine-truth document every OmP agent reads
 * and writes. Human operators never edit it directly — corrections flow
 * through the prompt channel, and the Orchestrator materialises them as
 * mutations here plus an append block in `journal.md`.
 *
 * Design rules for this schema:
 *
 * 1. **Forward-compat by default.** Every field an agent produces downstream
 *    of T04 is optional or defaulted, so the loader (T03) can seed a minimal
 *    `ChallengeState` from just a binary + Dockerfile without tripping
 *    validation. EnvSetup (T04), Reverser (T07), VulnHunter (T10), Exploiter
 *    (T14), and Verifier (T15) progressively fill in more fields.
 * 2. **Schema versioning.** `schema_version` is the first line of defense for
 *    state-format drift across sessions. Bump it on breaking changes and add
 *    an explicit migration path in `io.ts`.
 * 3. **No blobs inline.** Large artefacts (Reverser summaries, libc binaries,
 *    exploit scripts, Verifier logs) live on disk under `.omp/artifacts/`,
 *    `.omp/exploit/`, `.omp/logs/`. The schema only stores paths and metadata.
 * 4. **Timestamps are ISO-8601 strings.** Zod does not natively serialise
 *    `Date`, and ISO strings are human-readable when inspecting `state.json`.
 *
 * The full task catalog this schema supports lives in
 * `.omc/specs/deep-interview-oh-my-pwn.md` → "Derived Task List".
 */

import { z } from "zod"
import { CHALLENGE_STATE_SCHEMA_VERSION } from "./constants"

/**
 * ISO-8601 timestamp with mandatory timezone (Z or ±HH:MM).
 *
 * Validated by regex rather than left as a loose string because the journal
 * writer and correction protocol re-emit timestamps verbatim — a malformed
 * value that sneaks past the schema would crash `appendUserCorrection` when
 * it tries to round-trip through `new Date(...).toISOString()`.
 */
const IsoTimestampSchema = z.string().regex(
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$/u,
  { message: "Expected ISO-8601 timestamp with timezone (Z or ±HH:MM)" },
)

/** ELF mitigations as reported by checksec on the target binary. */
export const MitigationsSchema = z.object({
  nx: z.boolean().optional(),
  pie: z.boolean().optional(),
  canary: z.boolean().optional(),
  /** "full" | "partial" | "none" — keep loose for libc variance. */
  relro: z.string().optional(),
  /** True if the Dockerfile / runtime applies a seccomp policy. */
  seccomp: z.boolean().optional(),
  /** Raw checksec output, kept for audit. */
  raw: z.string().optional(),
})
export type Mitigations = z.infer<typeof MitigationsSchema>

/** Remote server reproduction wrapper (ynetd / socat / xinetd / bare). */
export const RemoteEntrypointSchema = z.object({
  host: z.string().default("127.0.0.1"),
  port: z.number().int().positive().optional(),
  /** e.g. "ynetd", "socat", "xinetd", "none". */
  wrapper: z.string().optional(),
  /** The exact command EnvSetup observed in the Dockerfile CMD/ENTRYPOINT. */
  command: z.string().optional(),
})
export type RemoteEntrypoint = z.infer<typeof RemoteEntrypointSchema>

/** A single leak captured mid-exploit (libc base, heap base, canary, ...). */
export const LeakEntrySchema = z.object({
  /** Short label: "libc_base", "heap_base", "stack_canary", "pie_base", etc. */
  name: z.string().min(1),
  /** Hex-encoded 64-bit value or raw string, depending on leak kind. */
  value: z.string().min(1),
  /** Stage id where the leak was obtained. */
  stage: z.string().optional(),
  discovered_at: IsoTimestampSchema,
  /** Free-form notes from the Exploiter about how the leak was obtained. */
  notes: z.string().optional(),
})
export type LeakEntry = z.infer<typeof LeakEntrySchema>

/** VulnHunter's ranked candidate entry. */
export const VulnCandidateSchema = z.object({
  id: z.string().min(1),
  /** Exploitation primitive tag: "stack_bof", "fmt_string_read", "tcache_poison", ... */
  primitive: z.string().min(1),
  /** Location hint: function name, offset, or source line. */
  location: z.string().optional(),
  /** 0.0–1.0 confidence from the hunter. */
  confidence: z.number().min(0).max(1).optional(),
  /** Why the hunter thinks this candidate is viable. */
  rationale: z.string().optional(),
  /** Optional libc range this candidate requires ("2.31-2.35"). */
  libc_range: z.string().optional(),
  /** Whether Exploiter has verified this candidate. */
  verified: z.boolean().optional(),
  /** Verification outcome: "confirmed", "disproved", or "inconclusive". */
  verification_result: z
    .enum(["confirmed", "disproved", "inconclusive"])
    .optional(),
})
export type VulnCandidate = z.infer<typeof VulnCandidateSchema>

/** Status of a single pipeline stage. */
export const StageStatusSchema = z.enum([
  "pending",
  "in_progress",
  "passed",
  "failed",
  "skipped",
])
export type StageStatus = z.infer<typeof StageStatusSchema>

/** One stage (exploit step) in the plan. StrategyAgent generates, Exploiter executes. */
export const StageEntrySchema = z.object({
  id: z.string().min(1),
  description: z.string().optional(),
  status: StageStatusSchema.default("pending"),
  /** Exploit scripts attempted for this stage, newest last. */
  attempts: z.array(z.string()).default([]),
  started_at: IsoTimestampSchema.optional(),
  finished_at: IsoTimestampSchema.optional(),
  /** Short failure reason if `status === "failed"`. */
  failure_reason: z.string().optional(),
  /** What this step proves (e.g., "ret address controllable at offset 0xa8"). */
  goal: z.string().optional(),
  /** Expected observation on success (e.g., "rip == 0xdeadbeef"). */
  expected_result: z.string().optional(),
  /** Link to vuln_candidates[].id this step is derived from. */
  candidate_id: z.string().optional(),
})
export type StageEntry = z.infer<typeof StageEntrySchema>

/** Correction block appended to the journal + applied to this state. */
export const UserCorrectionSchema = z.object({
  timestamp: IsoTimestampSchema,
  /** The user's original correction message (verbatim for audit). */
  user_text: z.string().min(1),
  /** Short summary of what the Orchestrator changed in state.json. */
  applied_delta: z.string().optional(),
})
export type UserCorrection = z.infer<typeof UserCorrectionSchema>

/**
 * ChallengeState — the single source of machine truth per challenge.
 *
 * Every field downstream of identity/input is optional so T03 can seed a
 * valid initial state from just `{binary_path, dockerfile_path}`.
 */
export const ChallengeStateSchema = z.object({
  /** Schema version; bump on breaking changes. */
  schema_version: z.string().default(CHALLENGE_STATE_SCHEMA_VERSION),

  /** Absolute path to the challenge folder that owns this state. */
  challenge_dir: z.string().min(1),

  /* ── Input contract (T03 fills) ───────────────────────────────────────── */

  /** Absolute path to the binary (the active one — see binary_patched). */
  binary_path: z.string().min(1),
  /**
   * SHA-256 of the binary bytes at `binary_path` *as it currently exists on
   * disk*. After T04 EnvSetup patches the interpreter (`binary_patched`
   * becomes true), this is the patched binary's hash, not the original's.
   * The original's hash is preserved in `binary_original_sha256`.
   */
  binary_sha256: z.string().optional(),
  /**
   * True iff T04 EnvSetup has run `patchelf --set-interpreter --set-rpath`
   * against `binary_path`. Implies `binary_original_path` and
   * `binary_original_sha256` are set.
   */
  binary_patched: z.boolean().optional(),
  /**
   * Absolute path to the untouched original binary, saved as a backup
   * before patchelf modified `binary_path`. Lives under
   * `<challenge-dir>/.omp/artifacts/`. The patcher reads this back when
   * re-patching, so re-running EnvSetup is idempotent.
   */
  binary_original_path: z.string().optional(),
  /**
   * SHA-256 of the original (pre-patch) binary. Preserved as the input
   * contract identity so a future correction protocol can detect when the
   * user dropped a different binary into the challenge folder.
   */
  binary_original_sha256: z.string().optional(),
  /** Absolute path to the Dockerfile (or docker-compose.yml). */
  dockerfile_path: z.string().min(1),
  /** True if C source (`chal.c` etc.) is present → Reverser is skipped. */
  source_present: z.boolean().default(false),
  /** Absolute path(s) to source files when present. */
  source_paths: z.array(z.string()).default([]),

  /* ── Environment (T04 EnvSetup fills) ─────────────────────────────────── */

  /** Detected glibc version e.g. "2.31", "2.35". */
  libc_version: z.string().optional(),
  /** Absolute path to the extracted libc inside `.omp/artifacts/`. */
  libc_path: z.string().optional(),
  /** Absolute path to the extracted ld-linux inside `.omp/artifacts/`. */
  ld_path: z.string().optional(),
  /** Absolute path to the built Docker image tag or id. */
  docker_image: z.string().optional(),
  mitigations: MitigationsSchema.optional(),
  remote: RemoteEntrypointSchema.optional(),

  /* ── Reverser (T07) ────────────────────────────────────────────────────── */

  /**
   * Path to the Reverser's structured analysis markdown under
   * `.omp/artifacts/reverser-analysis.md`. Contains program overview,
   * function map, per-function sections (renamed pseudocode + stack
   * frame + key annotations), imports, exports. VulnHunter (T10) reads
   * this file as its primary context input.
   */
  reverser_summary_path: z.string().optional(),
  /**
   * Path to the Reverser's narrative research report (English) under
   * `.omp/artifacts/reverser-research.md`. A prose-form summary of what
   * the Reverser found — for human reading and as a quick-orient
   * document for downstream agents. Distinct from the structured
   * analysis artifact; this one tells the story, not the reference.
   */
  reverser_research_path: z.string().optional(),
  /**
   * Path to the Korean version of the narrative research report under
   * `.omp/artifacts/reverser-research.ko.md`. Translation of
   * `reverser_research_path` into natural Korean prose with technical
   * terms kept in English per project convention.
   */
  reverser_research_ko_path: z.string().optional(),
  /** When the Reverser last completed analysis. */
  reverser_analyzed_at: IsoTimestampSchema.optional(),

  /* ── VulnHunter (T10) ──────────────────────────────────────────────────── */

  vuln_candidates: z.array(VulnCandidateSchema).default([]),
  /** Path to VulnHunter's analysis artifact (vulnhunter-analysis.md). */
  vulnhunter_analysis_path: z.string().optional(),
  /** When VulnHunter last completed analysis. */
  vulnhunter_analyzed_at: IsoTimestampSchema.optional(),

  /* ── Stage map + exploitation progress (T14 / T15 / T17) ──────────────── */

  stages: z.array(StageEntrySchema).default([]),
  current_stage_index: z.number().int().nonnegative().optional(),
  /** Path to the exploit script currently being iterated on. */
  current_exploit_script: z.string().optional(),

  /* ── Leak ledger (Exploiter fills mid-run) ─────────────────────────────── */

  leaks: z.array(LeakEntrySchema).default([]),

  /* ── Correction audit log (T20 prompt-driven correction protocol) ─────── */

  corrections: z.array(UserCorrectionSchema).default([]),

  /* ── Meta ──────────────────────────────────────────────────────────────── */

  created_at: IsoTimestampSchema,
  updated_at: IsoTimestampSchema,
})
export type ChallengeState = z.infer<typeof ChallengeStateSchema>

/**
 * Input required to seed a fresh ChallengeState. Everything else is defaulted
 * to empty so T03 (loader) can call this with the bare input contract.
 */
export interface InitialChallengeStateInput {
  challenge_dir: string
  binary_path: string
  dockerfile_path: string
  source_present?: boolean
  source_paths?: string[]
}

/**
 * Build a minimal valid ChallengeState for a fresh challenge. Use this from
 * T03's loader when initializing `.omp/state.json` for the first time.
 */
export function createInitialChallengeState(
  input: InitialChallengeStateInput,
  now: Date = new Date(),
): ChallengeState {
  const timestamp = now.toISOString()
  return ChallengeStateSchema.parse({
    schema_version: CHALLENGE_STATE_SCHEMA_VERSION,
    challenge_dir: input.challenge_dir,
    binary_path: input.binary_path,
    dockerfile_path: input.dockerfile_path,
    source_present: input.source_present ?? false,
    source_paths: input.source_paths ?? [],
    created_at: timestamp,
    updated_at: timestamp,
  })
}
