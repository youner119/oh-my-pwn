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

/** How a vulnerability candidate was discovered. */
export const CandidateOriginSchema = z.enum([
  /** Found during initial VulnHunter analysis pass. */
  "initial",
  /** Derived from a confirmed candidate via VulnHunter 2nd-pass analysis. */
  "derived",
  /** Discovered incidentally by Exploiter during verification (unexpected leak, heap state, etc.). */
  "incidental",
])
export type CandidateOrigin = z.infer<typeof CandidateOriginSchema>

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
  /** How this candidate was discovered. Defaults to "initial" for backward compat. */
  origin_type: CandidateOriginSchema.optional(),
  /** For derived/incidental candidates: the confirmed candidate id that triggered discovery. */
  derived_from: z.string().optional(),
  /** Path to the PoC script that proves this primitive works. */
  poc_script_path: z.string().optional(),
  /** What this verified primitive provides (e.g., "libc_base", "arbitrary_write", "rip_control"). */
  gives: z.array(z.string()).optional(),
  /** What this primitive requires from other verified primitives (e.g., "libc_base" for ROP). */
  needs: z.array(z.string()).optional(),
  /** For combined primitives: IDs of candidates that were combined to create this one. */
  combined_from: z.array(z.string()).optional(),
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

/** Parallel pipeline configuration. Orchestrator reads this to decide instance counts and budget. */
export const ParallelConfigSchema = z.object({
  /** Number of VulnHunter ensemble instances to spawn. */
  vh_instance_count: z.number().int().min(1).default(3),
  /** Number of StrategyAgent+Exploiter pairs to run in parallel (one per candidate). */
  sa_instance_count: z.number().int().min(1).default(3),
  /**
   * Safety-net cycle cap for autonomous mode. Orchestrator's normal
   * termination is LLM-judged stagnation (no progress) or success
   * (flag/shell); this cap only fires if the loop runs away.
   */
  max_cycles: z.number().int().min(1).default(20),
  /** Max retries per candidate before escalating to next candidate. */
  max_retries_per_candidate: z.number().int().min(1).default(3),
})
export type ParallelConfig = z.infer<typeof ParallelConfigSchema>

/** Current phase of the parallel pipeline. */
export const PipelinePhaseSchema = z.enum([
  "idle",
  "vh_ensemble",
  "strategy_exploit",
  "cascading",
  "terminated",
])
export type PipelinePhase = z.infer<typeof PipelinePhaseSchema>

/** Why the pipeline terminated. */
export const TerminationReasonSchema = z.enum([
  "flag_found",
  "exhausted",
  "budget_exceeded",
  "user_intervention",
])
export type TerminationReason = z.infer<typeof TerminationReasonSchema>

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

  /**
   * Absolute path to the binary OmP operates on.
   *
   * **Semantics depend on whether the omp-setup agent has run:**
   * - Pre-setup (T03 loader phase): points at the loader's chosen file
   *   inside the challenge folder (e.g. `deploy/prob`). Same as
   *   `binary_input_path`.
   * - Post-setup (omp-setup agent, see `.omc/specs/deep-interview-envsetup-agent.md`):
   *   points at the **patched copy** under `.omp/artifacts/<basename>`.
   *   The original input file is preserved at `binary_input_path` and is
   *   never mutated (patchelf in-place was retired with the omp-setup agent
   *   to keep `docker build` deterministic).
   *
   * Reverser / VulnHunter / Strategist / Exploiter read this field as
   * "the binary to analyse / exploit against". They do not need to know
   * whether it is the input or the patched copy.
   */
  binary_path: z.string().min(1),
  /**
   * SHA-256 of the binary bytes at `binary_path` *as it currently exists on
   * disk*. Post-setup, this is the patched binary's hash. The original
   * input's hash is preserved separately in `binary_input_sha256`
   * (formerly `binary_original_sha256`, now deprecated).
   */
  binary_sha256: z.string().optional(),
  /**
   * Absolute path to the **untouched input binary**. The omp-setup agent
   * never modifies this file — this is the canonical input identity the
   * challenge owner provided (`deploy/prob`, etc.). `binary_path` is a
   * separate patched copy under `.omp/artifacts/`. Equal to `binary_path`
   * during the pre-setup phase (T03 loader output).
   *
   * Added by spec `deep-interview-envsetup-agent.md` (T01).
   */
  binary_input_path: z.string().min(1).optional(),
  /**
   * SHA-256 of the untouched input binary. Used as the **challenge
   * identity** for setup-gate idempotency: the orchestrator skips
   * re-running the setup agent only when this hash matches the file
   * currently at `binary_input_path`. Stale binary (user replaced the
   * file) → mismatch → force re-setup.
   *
   * Added by spec `deep-interview-envsetup-agent.md` (T01). Supersedes
   * `binary_original_sha256`.
   */
  binary_input_sha256: z.string().optional(),
  /**
   * @deprecated Use `setup_complete` instead. The omp-setup agent retired
   * in-place patchelf, so the boolean "is patched" gate is replaced by the
   * richer setup-gate (`setup_complete` + `setup_unsupported_reason`).
   * Schema retains the field to keep historical state.json parseable.
   */
  binary_patched: z.boolean().optional(),
  /**
   * @deprecated Use `binary_input_path` instead. Was the in-place patchelf
   * backup under `.omp/artifacts/<basename>.orig`. With in-place patching
   * retired, the input file at `binary_input_path` is itself canonical and
   * no backup is needed.
   */
  binary_original_path: z.string().optional(),
  /**
   * @deprecated Use `binary_input_sha256` instead.
   */
  binary_original_sha256: z.string().optional(),
  /** Absolute path to the Dockerfile (or docker-compose.yml). */
  dockerfile_path: z.string().min(1),
  /** True if C source (`chal.c` etc.) is present → Reverser is skipped. */
  source_present: z.boolean().default(false),
  /** Absolute path(s) to source files when present. */
  source_paths: z.array(z.string()).default([]),

  /* ── Setup gate (T01 omp-setup agent) ────────────────────────────────── */

  /**
   * Challenge classification decided by the omp-setup agent in Phase 0
   * (inspect & classify). Currently only "user-mode-elf" is supported;
   * everything else lands in "unsupported" and the orchestrator hands off
   * to the user with `setup_unsupported_reason`. Future challenge types
   * (kernel, library-only, multi-binary, source-only, browser, …) will be
   * added as separate enum values when their sub-flows are specified.
   *
   * Added by spec `deep-interview-envsetup-agent.md` (T01).
   */
  challenge_type: z.enum(["user-mode-elf", "unsupported"]).optional(),
  /**
   * Setup-gate boolean. `true` means the omp-setup agent finished
   * successfully and downstream agents (Reverser/VH/SA/Exploiter) may
   * proceed. `false` or `undefined` means setup is needed.
   *
   * The orchestrator skips the setup agent only when this is `true` AND
   * `binary_input_sha256` matches the file currently at `binary_input_path`.
   *
   * Added by spec `deep-interview-envsetup-agent.md` (T01).
   */
  setup_complete: z.boolean().optional(),
  /**
   * Free-form reason set by the omp-setup agent when it cannot proceed
   * (e.g. `"kernel challenge detected: vmlinux + qemu-system in run.sh"`,
   * `"host verify failed: missing libz.so.1"`). `null` (or `undefined`)
   * means setup succeeded. Any non-null value tells the orchestrator to
   * stop with a user handoff — diagnostic detail goes in the journal.
   *
   * Added by spec `deep-interview-envsetup-agent.md` (T01).
   */
  setup_unsupported_reason: z.string().nullable().optional(),

  /* ── Environment (T04 EnvSetup / omp-setup agent fills) ──────────────── */

  /** Detected glibc version e.g. "2.31", "2.35". `"static"` for static binaries. */
  libc_version: z.string().optional(),
  /**
   * Absolute path to the extracted libc inside `.omp/artifacts/`.
   *
   * Post-omp-setup-agent: this is an **alias** for
   * `extracted_libs["libc.so.6"]` kept for backward compatibility — existing
   * prompts (`omp-strategist`, `omp-exploiter`) and the envsetup library
   * read this field directly. Setup agent populates both.
   */
  libc_path: z.string().optional(),
  /**
   * Absolute path to the extracted ld-linux inside `.omp/artifacts/`.
   *
   * Post-omp-setup-agent: alias for `extracted_libs[<ld basename>]` (e.g.
   * `extracted_libs["ld-linux-x86-64.so.2"]`). Kept for backward compat.
   */
  ld_path: z.string().optional(),
  /**
   * Full NEEDED-library map extracted from the docker image, keyed by the
   * SONAME / DT_NEEDED entry (`"libc.so.6"`, `"libm.so.6"`, `"libz.so.1"`,
   * `"libbz2.so.1.0"`, `"liblzma.so.5"`, `"ld-linux-x86-64.so.2"`, …).
   * Values are absolute paths under `.omp/artifacts/`.
   *
   * Static binaries: empty map. `libc_version` is `"static"` in that case.
   *
   * Symlink policy: keys are NEEDED names (which may be symlinks pointing
   * at the real file in the same directory). Whether the value is a
   * symlink or a dereferenced realfile is controlled by the
   * `omp_setup_extract_file` `dereference_symlinks` option.
   *
   * Added by spec `deep-interview-envsetup-agent.md` (T01).
   */
  extracted_libs: z.record(z.string(), z.string()).optional(),
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
  /**
   * Directory containing raw decompiled pseudocode files saved by
   * BN MCP `decompile_to_file` tool. Path: `<challenge-dir>/.omp/artifacts/pseudocode/`.
   * Each file is `<function_name>.txt` with the full BN HLIL output —
   * no LLM intermediation. VulnHunter reads these for detailed analysis
   * beyond the Reverser summary.
   */
  pseudocode_dir: z.string().optional(),
  /**
   * Path to the Binary Ninja analysis database (.bndb) saved by
   * `save_bndb`. User can open this in BN GUI to review all renames,
   * types, and comments applied by the Reverser.
   */
  bndb_path: z.string().optional(),
  /** When the Reverser last completed analysis. */
  reverser_analyzed_at: IsoTimestampSchema.optional(),

  /* ── VulnHunter (T10) ──────────────────────────────────────────────────── */

  vuln_candidates: z.array(VulnCandidateSchema).default([]),
  /** Path to VulnHunter's analysis artifact (vulnhunter-analysis.md). */
  vulnhunter_analysis_path: z.string().optional(),
  /** When VulnHunter last completed analysis. */
  vulnhunter_analyzed_at: IsoTimestampSchema.optional(),

  /* ── StrategyAgent (T14) ────────────────────────────────────────────────── */

  /** Path to StrategyAgent's plan artifact (strategist-plan.md). */
  strategist_plan_path: z.string().optional(),
  /** When StrategyAgent last designed/updated the plan. */
  strategist_planned_at: IsoTimestampSchema.optional(),

  /* ── Stage map + exploitation progress (T14 / T16) ─────────────────────── */

  stages: z.array(StageEntrySchema).default([]),
  current_stage_index: z.number().int().nonnegative().optional(),
  /** Path to the exploit script currently being iterated on. */
  current_exploit_script: z.string().optional(),

  /* ── Leak ledger (Exploiter fills mid-run) ─────────────────────────────── */

  leaks: z.array(LeakEntrySchema).default([]),

  /* ── Parallel pipeline state (T18 parallel orchestration) ────────────── */

  /** Parallel execution configuration. Orchestrator sole writer sets this. */
  parallel_config: ParallelConfigSchema.optional(),
  /** Current phase of the parallel pipeline. */
  pipeline_phase: PipelinePhaseSchema.optional(),
  /** Current VH→SA→Exploiter→cascading cycle number (1-based). */
  pipeline_cycle: z.number().int().nonnegative().optional(),
  /** Why the pipeline terminated (set when pipeline_phase === "terminated"). */
  pipeline_termination_reason: TerminationReasonSchema.optional(),

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
