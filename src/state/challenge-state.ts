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
 * 1. **Forward-compat by default.** Every field beyond `challenge_dir` is
 *    optional or defaulted, so the loader (`omp_load_challenge`) can seed a
 *    minimal `ChallengeState` from just the challenge directory without
 *    tripping validation. omp-setup Phase 0 (Detect) writes
 *    `binary_input_path` / `binary_input_sha256` / `dockerfile_path` /
 *    `source_*`; later phases (Phase 1–5) and downstream agents (Reverser,
 *    VulnHunter, Strategist, Exploiter) progressively fill in more fields.
 *    See `.omc/specs/contract-load-detect-split.md` (D1, D2).
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

/**
 * CET (Control-flow Enforcement Technology). The IBT/SHSTK **marking** is a
 * static ELF property (`.note.gnu.property`) that checksec reads, but actual
 * **enforcement** is environment-dependent (CPU + kernel + glibc/ld + tunables).
 * A binary can be marked yet run with CET off — so marking ≠ enforced. omp-setup
 * measures `enforced` at container-verify runtime (`/proc/<pid>/status`
 * `x86_Thread_features` / shadow-stack VMA), the one place it actually runs the
 * binary. Downstream agents MUST treat IBT/SHSTK as a blocker only when
 * `enforced === true` — never from the marking alone.
 */
export const CetSchema = z.object({
  /** ELF `.note.gnu.property` advertises IBT. */
  ibt_marked: z.boolean(),
  /** ELF `.note.gnu.property` advertises SHSTK. */
  shstk_marked: z.boolean(),
  /** Runtime enforcement measured at container verify. `null` = not measured. */
  enforced: z.boolean().nullable(),
})
export type Cet = z.infer<typeof CetSchema>

/**
 * Target binary mitigations. **Structured, not raw checksec text.** Static
 * mitigations (nx / pie / canary / relro) are read straight from the ELF and
 * recorded verbatim; `seccomp` comes from the Dockerfile/runtime; `cet` carries
 * the static marking PLUS the runtime-measured enforcement (see {@link CetSchema}).
 */
export const MitigationsSchema = z.object({
  nx: z.boolean().optional(),
  pie: z.boolean().optional(),
  canary: z.boolean().optional(),
  /** "full" | "partial" | "none" — keep loose for libc variance. */
  relro: z.string().optional(),
  /** True if the Dockerfile / runtime applies a seccomp policy. */
  seccomp: z.boolean().optional(),
  /** CET marking (static) + enforcement (runtime-measured). Omitted if no CET note. */
  cet: CetSchema.optional(),
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

/** How a vulnerability candidate was discovered. */
export const CandidateOriginSchema = z.enum([
  /** Found during initial VulnHunter analysis pass. */
  "initial",
  /** Derived from a confirmed candidate via VulnHunter 2nd-pass analysis. */
  "derived",
  /**
   * Legacy / forward-compat only. The active pipeline no longer produces
   * `incidental` candidates: VH is the sole producer of `vuln_candidates`,
   * and SA/Exploiter report findings via `verification_blockers` (verification
   * methodology) or by signalling vh_pending (new exploration angle) instead
   * of inventing candidates themselves. Kept in the enum so historical
   * state.json files still parse.
   */
  "incidental",
])
export type CandidateOrigin = z.infer<typeof CandidateOriginSchema>

/**
 * VulnCandidate split — Summary + Detail.
 *
 * Spec: `.omc/specs/state-split-vuln-candidates.md` (D2/D6 — strict sole
 * writer + per-file detail).
 *
 * - Summary = `state.json.vuln_candidates[]` (Orchestrator sole writer).
 * - Detail  = `.omp/candidates/<id>.json` (Orchestrator sole writer).
 *
 * Combined `VulnCandidateSchema` = `Summary.merge(Detail)` — used by
 * `omp_create_candidate` / `omp_patch_candidate` payloads (P3) and the
 * sub-agent `result.new_candidate` return value (D3.1).
 */

/** Summary fields — agent prompt context, state.json 의 vuln_candidates array. */
export const VulnCandidateSummarySchema = z.object({
  id: z.string().min(1),
  /** Exploitation primitive tag: "stack_bof", "fmt_string_read", "tcache_poison", ... */
  primitive: z.string().min(1),
  /**
   * Verification outcome set by the Orchestrator after StrategyAgent +
   * Exploiter run. Presence of this field IS the verification flag —
   * `verification_result === undefined` means the candidate has not been
   * verified yet. States:
   * - `confirmed` — mechanic demonstrated AND its `needs` were actually
   *   satisfied by confirmed upstream primitives (real earned values in the
   *   run, self-contained otherwise). Genuinely usable.
   * - `mechanism_confirmed` — the mechanic/technique was demonstrated, but only
   *   under an orchestrator-AUTHORIZED assumed input (a `needs` value injected /
   *   assumed, not earned end-to-end — e.g. a leak-assumed GDB pre-verify). NOT
   *   usable until a real chain proves it; the end-to-end proof is a separate
   *   combine candidate. Every assumed dependency MUST be declared in `needs`.
   *   An UNauthorized out-of-band shortcut (e.g. reading pie_base from
   *   /proc/<pid>/maps) is NOT this — it is a rule violation → `inconclusive`.
   * - `failed` — disproved.
   * - `inconclusive` — mechanic not demonstrated (couldn't run, harness broke,
   *   or a needed capability was unavailable and not authorized to assume).
   */
  verification_result: z
    .enum(["confirmed", "mechanism_confirmed", "failed", "inconclusive"])
    .optional(),
  /** Producing sub-agent (e.g. "VH-3" / "SA-04"). Trace of provenance. */
  agent: z.string().min(1).optional(),
  /** For combined / derived candidates: source candidate ids. */
  combined_from: z.array(z.string()).optional(),
  /**
   * Short claim of *what* this candidate is. VH / SA produces, Orchestrator
   * forwards. Distinct from `rationale` (detail file — full reasoning of *why*).
   */
  description: z.string().optional(),
  /** Derived counters — Orchestrator syncs from detail at patch time. */
  gives_count: z.number().int().min(0).optional(),
  needs_count: z.number().int().min(0).optional(),
  /** Whether `detail.poc_script_path` is set (boolean for summary visibility). */
  has_poc: z.boolean().optional(),
})
export type VulnCandidateSummary = z.infer<typeof VulnCandidateSummarySchema>

/** Detail fields — `.omp/candidates/<id>.json`. Heavy reasoning + lists. */
export const VulnCandidateDetailSchema = z.object({
  /** Location hint: function name, offset, or source line. */
  location: z.string().optional(),
  /** 0.0–1.0 confidence from the hunter. */
  confidence: z.number().min(0).max(1).optional(),
  /** Why the hunter thinks this candidate is viable (full reasoning). */
  rationale: z.string().optional(),
  /** Optional libc range this candidate requires ("2.31-2.35"). */
  libc_range: z.string().optional(),
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
  /**
   * SA-reported verification methodology issues that blocked the verify task
   * (e.g. PIE base translation needed, GDB attach failed for tooling reason).
   * NOT a vulnerability primitive — these are tool/method corrections forwarded
   * to the next SA spawn for the same candidate. VH is the sole producer of
   * vuln_candidates; SA must never invent a new candidate to express a
   * verification failure cause.
   */
  verification_blockers: z
    .array(
      z.object({
        cause: z.string().min(1),
        suggested_fix: z.string().optional(),
        retry_recommended: z.boolean().default(false),
      }),
    )
    .optional(),
})
export type VulnCandidateDetail = z.infer<typeof VulnCandidateDetailSchema>

/** Combined — summary + detail. Used by create/patch tool payloads and sub-agent return values. */
export const VulnCandidateSchema = VulnCandidateSummarySchema.merge(
  VulnCandidateDetailSchema,
)
export type VulnCandidate = z.infer<typeof VulnCandidateSchema>

/** Parallel pipeline configuration. Orchestrator reads this to decide instance counts and budget. */
export const ParallelConfigSchema = z.object({
  /** Number of VulnHunter ensemble instances to spawn. */
  vh_instance_count: z.number().int().min(1).default(10),
  /** Number of StrategyAgent+Exploiter pairs to run in parallel (one per candidate). */
  sa_instance_count: z.number().int().min(1).default(10),
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
 * Setup-side blocker that omp-setup writes when it cannot proceed without
 * Orchestrator (and ultimately user) input. The Orchestrator inspects
 * `state.setup_blocker` after every setup subagent return and, if present,
 * resolves the blocker (e.g. asks the user to disambiguate the binary, seeds
 * `binary_input_path` via `omp_patch_state`, clears `setup_blocker`) before
 * relaunching setup.
 *
 * Added by `.omc/specs/contract-load-detect-split.md` (D5).
 */
export const SetupBlockerSchema = z.object({
  /**
   * `"ambiguous-binary"` — Phase 0 detect scanned `challenge_dir` and found
   * multiple ELF candidates. `candidates` lists absolute paths the user
   * should choose between. Resolution: Orchestrator picks one (user
   * disambig) and writes it to `binary_input_path` via `omp_patch_state`,
   * then clears `setup_blocker` and relaunches omp-setup.
   *
   * The kind is a literal-string union so additional blocker shapes can be
   * added later without breaking parsers.
   */
  kind: z.literal("ambiguous-binary"),
  /** Absolute paths of binary candidates the user should choose between. */
  candidates: z.array(z.string().min(1)).min(2),
  /** Human-readable explanation appended to the journal alongside this blocker. */
  message: z.string().min(1),
})
export type SetupBlocker = z.infer<typeof SetupBlockerSchema>

/**
 * ChallengeState — the single source of machine truth per challenge.
 *
 * Every field beyond `challenge_dir` is optional so the loader
 * (`omp_load_challenge`) can seed a valid initial state from just the
 * challenge directory. omp-setup Phase 0 (Detect) writes the input-contract
 * fields (`binary_input_path` / `dockerfile_path` / `source_*`) via
 * `omp_patch_state` after scanning `challenge_dir`. See
 * `.omc/specs/contract-load-detect-split.md` (D1, D2).
 */
export const ChallengeStateSchema = z.object({
  /** Schema version; bump on breaking changes. */
  schema_version: z.string().default(CHALLENGE_STATE_SCHEMA_VERSION),

  /** Absolute path to the challenge folder that owns this state. */
  challenge_dir: z.string().min(1),

  /* ── Input contract (omp-setup Phase 0 Detect fills) ──────────────────── */

  /**
   * Absolute path to the **patched binary** that downstream agents
   * (Reverser / VulnHunter / Strategist / Exploiter) analyse and exploit
   * against. Written **only** by the omp-setup agent in Phase 3 (dynamic-
   * linked) or mirrored from `binary_input_path` in Phase 2 (static-linked
   * branch). The loader does NOT seed this field — it remains `undefined`
   * until omp-setup runs, which is correct because the patched copy
   * literally does not exist on disk before Phase 3 produces it.
   *
   * Dynamic-linked post-setup: `<challenge_dir>/.omp/artifacts/<basename>`
   * with patched interpreter + `--replace-needed` rewrites. Distinct from
   * `binary_input_path` (which is preserved untouched).
   *
   * Static-linked post-setup: equal to `binary_input_path` because no
   * patchelf is applied — but the omp-setup agent still explicitly mirrors
   * the field so the post-setup invariant "`binary_path` populated iff
   * `setup_complete === true` AND `challenge_type === 'user-mode-elf'`"
   * holds uniformly within the supported branch.
   *
   * **Mode 0/9 (unsupported) branch:** Phase 1–5 are skipped, so this
   * field stays `undefined` even when `setup_complete === true`. Mode 0
   * Exploiter reads `binary_input_path` instead (the untouched input
   * identity), since there is no patched copy to analyse. See
   * `.omc/specs/deep-interview-mode-0-9-setup.md` (ACS-4).
   *
   * Downstream agents read this field through the `setup_complete === true`
   * gate enforced by the Orchestrator's Phase 0 wait_all, so they never
   * see the pre-setup `undefined` state. Mode 0 dispatch additionally
   * gates on `challenge_type === "unsupported"` and reads
   * `binary_input_path` directly.
   */
  binary_path: z.string().min(1).optional(),
  /**
   * SHA-256 of the bytes at `binary_path` as they exist on disk. Set by the
   * omp-setup agent in Phase 3 alongside `binary_path`. Diverges from
   * `binary_input_sha256` for dynamic-linked binaries (patched bytes) and
   * equals it for the static-linked branch.
   */
  binary_sha256: z.string().optional(),
  /**
   * Absolute path to the **untouched input binary** — the canonical input
   * identity the challenge owner provided (`deploy/prob`, etc.). Seeded by
   * the **omp-setup agent in Phase 0 (Detect)** from the binary candidate it
   * resolved by scanning `challenge_dir`, and never mutated thereafter (the
   * setup agent makes a separate patched copy at `binary_path`; downstream
   * agents must NOT execute or analyse `binary_input_path` directly
   * post-setup — its interpreter still points at the image's ld).
   *
   * `undefined` when omp-setup classified the challenge as `"unsupported"`
   * with no ELF binary present (kernel image / source-only / browser /
   * library-only). Downstream Mode 0/9 dispatch handles the no-binary
   * branch separately.
   *
   * Added by spec `deep-interview-envsetup-agent.md` (T01). Phase-0 detect
   * ownership added by `.omc/specs/contract-load-detect-split.md` (D2).
   */
  binary_input_path: z.string().min(1).optional(),
  /**
   * SHA-256 of the untouched input binary. Seeded by the omp-setup agent in
   * Phase 0 (Detect) alongside `binary_input_path`. Kept on the state for
   * informational purposes (journal/audit), but no longer used as an
   * idempotency key — setup-gate idempotency is now `setup_complete === true`
   * single-condition. Binary replacement requires `rm -rf .omp/` + reload.
   *
   * Added by spec `deep-interview-envsetup-agent.md` (T01). Idempotency-key
   * role removed by `.omc/specs/contract-load-detect-split.md` (D4).
   */
  binary_input_sha256: z.string().optional(),
  /**
   * Absolute path to the Dockerfile (or docker-compose.yml). Seeded by the
   * omp-setup agent in Phase 0 (Detect). `undefined` when no Dockerfile is
   * present in `challenge_dir` (Phase 1 docker build skipped, Mode 0/9
   * dispatch).
   *
   * Required → optional by `.omc/specs/contract-load-detect-split.md` (D3).
   */
  dockerfile_path: z.string().min(1).optional(),
  /**
   * True if C/C++ source (`chal.c` etc.) is present. Seeded by the omp-setup
   * agent in Phase 0 (Detect). Reverser short-circuits when this is `true`.
   *
   * Detect ownership moved from loader → setup by
   * `.omc/specs/contract-load-detect-split.md` (D2).
   */
  source_present: z.boolean().default(false),
  /** Absolute path(s) to source files when present. Seeded by omp-setup Phase 0. */
  source_paths: z.array(z.string()).default([]),
  /**
   * Setup-side blocker requiring Orchestrator (user) resolution. Currently
   * only `"ambiguous-binary"` is defined — Phase 0 detect found multiple ELF
   * candidates. Orchestrator clears this after seeding `binary_input_path`
   * via `omp_patch_state` and relaunches omp-setup. See `SetupBlockerSchema`.
   *
   * Added by `.omc/specs/contract-load-detect-split.md` (D5).
   */
  setup_blocker: SetupBlockerSchema.optional(),

  /* ── Setup gate (T01 omp-setup agent) ────────────────────────────────── */

  /**
   * Absolute host path to the OmP plugin's canonical workspace mount source
   * (`<plugin-root>/workspace/`). Seeded by `omp_load_challenge` from the
   * plugin's `OMP_WORKSPACE_PATH` constant so every agent — Setup, Reverser,
   * VH, SA, Exploiter — can derive per-challenge container paths
   * deterministically without bash-time inference.
   *
   * Setup agent uses this together with `binary_input_sha256` and
   * `basename(challenge_dir)` to compute the per-challenge workspace
   * subdirectory `<workspace_root>/omp-<basename>-<sha8>/` in Phase 5.
   *
   * Added by spec `deep-interview-envsetup-agent.md` (T01.6).
   */
  workspace_root: z.string().optional(),
  /**
   * Challenge classification decided by the omp-setup agent in Phase 0
   * (inspect & classify). Two values:
   *
   * - `"user-mode-elf"` — single x86_64/i386 user-mode ELF target;
   *   Phase 1–5 (docker build, dependency discovery, patchelf, runtime
   *   verify) all run. Downstream agents read the **patched** binary at
   *   `binary_path`.
   * - `"unsupported"` — any other shape (kernel / browser / arm-userland
   *   / library-only / multi-binary / source-only / other) as classified
   *   by Phase 0. `unsupported_kind` names the bucket, Phase 1–5 are
   *   skipped, and the Orchestrator dispatches Mode 0 (autonomous
   *   fallback against `binary_input_path`); the user may override with
   *   Mode 9. See `.omc/specs/deep-interview-mode-0-9-setup.md`.
   *
   * Added by spec `deep-interview-envsetup-agent.md` (T01); Mode 0/9
   * semantics added by `deep-interview-mode-0-9-setup.md`.
   */
  challenge_type: z.enum(["user-mode-elf", "unsupported"]).optional(),
  /**
   * Setup-gate boolean. `true` means the omp-setup agent finished its
   * relevant phases and the Orchestrator may dispatch downstream work:
   *
   * - `challenge_type === "user-mode-elf"`: Phase 1–5 completed.
   *   Downstream agents (Reverser/VH/SA/Exploiter) proceed against the
   *   patched binary at `binary_path`.
   * - `challenge_type === "unsupported"`: Phase 0 classification
   *   completed. Identity fields are seeded **when present** —
   *   `binary_input_path` / `binary_input_sha256` are `undefined` for
   *   no-binary unsupported buckets (kernel image / source-only); other
   *   identity fields (`challenge_summary` / `setup_unsupported_reason` /
   *   `unsupported_kind`) are always set. Phase 1–5 are skipped, so
   *   `binary_path` / `binary_sha256` / `libc_path` / `ld_path` /
   *   `extracted_libs` / `libc_version` / `docker_image` / `mitigations` /
   *   `remote` stay `undefined`. The Orchestrator dispatches Mode 0 / 9.
   *
   * `false` or `undefined` means setup is needed.
   *
   * Setup-gate idempotency: the orchestrator skips the setup agent when
   * this is `true`. No sha-match check — binary replacement requires
   * `rm -rf .omp/` + reload (see `.omc/specs/contract-load-detect-split.md`
   * D4).
   *
   * Added by spec `deep-interview-envsetup-agent.md` (T01); Mode 0/9
   * branch added by `deep-interview-mode-0-9-setup.md` (ACS-4);
   * sha-match removed by `.omc/specs/contract-load-detect-split.md` (D4);
   * no-binary unsupported branch by same spec (D3).
   */
  setup_complete: z.boolean().optional(),
  /**
   * Free-form reason set by the omp-setup agent when Phase 1–5 are
   * skipped — either Phase 0 classified as `unsupported` (e.g.
   * `"kernel challenge detected: vmlinux + qemu-system in run.sh"`) or
   * a later phase hit a diagnose-only failure (e.g.
   * `"host verify failed: missing libz.so.1"`). `null` (or `undefined`)
   * means Phase 1–5 ran cleanly.
   *
   * Any non-null value indicates Phase 1–5 were skipped. The Orchestrator
   * dispatches Mode 0 against the input identity in that case; the user
   * may override with Mode 9. Diagnostic detail goes in the journal.
   *
   * Added by spec `deep-interview-envsetup-agent.md` (T01); Mode 0/9
   * dispatch semantics added by `deep-interview-mode-0-9-setup.md`.
   */
  setup_unsupported_reason: z.string().nullable().optional(),
  /**
   * Fine-grained classification of an unsupported challenge, set by the
   * omp-setup agent in Phase 0 alongside `challenge_type === "unsupported"`
   * and `setup_unsupported_reason`. Picks the bucket whose ctf-pwn knowledge
   * file the Mode 0 Exploiter lazy-reads; `"other"` covers shapes that do
   * not map to a dedicated knowledge bucket.
   *
   * Only meaningful when `challenge_type === "unsupported"`. For
   * `"user-mode-elf"` (the supported branch) this field is omitted.
   *
   * Added by spec `deep-interview-mode-0-9-setup.md` (T1 / ACS-2).
   */
  unsupported_kind: z
    .enum([
      "kernel-pwn",
      "arm-userland",
      "multi-binary",
      "browser",
      "library-only",
      "source-only",
      "other",
    ])
    .optional(),
  /**
   * 1–3 sentence free-form summary of the challenge environment, written
   * by the omp-setup agent during Phase 0 (Inspect & Understand). Captures
   * facts only — file kinds, mitigations raw flags, libc version, remote
   * wrapper, architecture — and explicitly NOT downstream judgments
   * (vulnerability primitives, mitigation strength, exploit feasibility,
   * function-level vuln hints, difficulty ratings) per D10 of
   * `.omc/specs/deep-interview-envsetup-agent.md`. Used by Reverser/VH as
   * a quick-orient input alongside `reverser-analysis.md`.
   *
   * Examples (allowed):
   *   "Ubuntu 24.04 / glibc 2.39 user-mode x86_64 ELF. Single binary 'prob'
   *    (8MB) with NEEDED libc/libm/libz/libbz2/liblzma. Mitigations:
   *    NX=on PIE=on Canary=on RELRO=full seccomp=false. Remote via xinetd
   *    on TCP/10039."
   *
   *   "Linux kernel exploitation challenge. bzImage + rootfs.cpio.gz +
   *    qemu-system-x86_64 boot with KASLR/SMAP/SMEP/PTI. Remote: socat
   *    TCP-LISTEN:8080."
   *
   * Counter-example (FORBIDDEN — violates D10):
   *   "Stack BOF in main() with 0x40 byte buffer. ROP straightforward,
   *    libc 2.39 means tcache double-free is fastbin-segregated."
   *
   * Added by spec `deep-interview-envsetup-agent.md` (T01.5).
   */
  challenge_summary: z.string().optional(),

  /* ── Environment (T04 EnvSetup / omp-setup agent fills) ──────────────── */

  /** Detected glibc version e.g. "2.31", "2.35". `"static"` for static binaries. */
  libc_version: z.string().optional(),
  /**
   * Absolute path to the extracted libc inside `.omp/artifacts/`.
   *
   * Post-omp-setup-agent: this is an **alias** for
   * `extracted_libs["libc.so.6"]` kept for backward compatibility — existing
   * prompts (`omp-strategist`, `omp-exploiter-mode-*`) and the envsetup
   * library read this field directly. Setup agent populates both.
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

  /**
   * Merged + deduped vulnerability candidate list. Written by the
   * Orchestrator from the JSON arrays returned by each VulnHunter
   * ensemble instance — VulnHunter agents themselves do not call
   * `omp_patch_state`. (`vulnhunter_analysis_path` / `vulnhunter_analyzed_at`
   * existed in the pre-ensemble T10 design and were retired with the
   * parallel orchestration cutover; markdown artifact is gone too.)
   */
  /**
   * Candidate summary array (spec: state-split-vuln-candidates.md). Detail =
   * `.omp/candidates/<id>.json`. Orchestrator sole writer.
   */
  vuln_candidates: z.array(VulnCandidateSummarySchema).default([]),

  /* ── StrategyAgent (T14) ────────────────────────────────────────────────── */

  // StrategyAgent operates state-only — no markdown plan artifact, no
  // dedicated state field. Plan state lives in `stages[]` +
  // `vuln_candidates[].verification_result` / `gives` / `needs` /
  // `combined_from`. (`strategist_plan_path` / `strategist_planned_at`
  // existed in an earlier T14 sketch and were retired with the
  // parallel orchestration cutover — "PoC code is the unit of
  // knowledge", per `.omc/specs/deep-interview-parallel-orchestration.md`.)

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

  /* ── Free-form metadata (setup / orchestrator writable) ──────────────── */

  /**
   * Free-form challenge-specific metadata that does not fit the fixed
   * schema. Use cases that motivated this field (added by
   * `.omc/specs/contract-load-detect-split.md` D7):
   *
   * - Kernel CTF (`challenge_type: "unsupported"`,
   *   `unsupported_kind: "kernel-pwn"`): `kernel_vmlinux_path` /
   *   `kernel_bzimage_path` / `kernel_initramfs_path` / `kernel_qemu_cmd` /
   *   `kernel_kaslr` (bool) / `kernel_smap` / `kernel_smep` / `kernel_pti` /
   *   `kernel_kpti` etc. The Mode 0 Exploiter reads these to drive its
   *   PoC against `qemu-system-*` rather than a user-mode ELF.
   * - Source-only: `source_build_cmd` (string), `source_build_outputs`
   *   (array<string>).
   * - Library-only: `library_host_binary` (path), `library_load_method`
   *   (`"dlopen"` / `"LD_PRELOAD"` / etc).
   * - Multi-binary: `binary_roles` (map<role-name, path>).
   * - User-mode-elf with non-standard env: anything the fixed schema
   *   does not already cover.
   *
   * **Write policy (POLICY-ENFORCED, not physically enforced):**
   * - **Allowed writers:** `omp-setup` (Phase 0 detect + Phase 1–5 env
   *   observation), `omp-orchestrator` (user corrections, D5 disambig
   *   side-channel data, recovery hints).
   * - **Forbidden writers:** `omp-reverser`, `omp-vulnhunter`,
   *   `omp-strategist`, `omp-exploiter`. These agents may **read** `etc`
   *   freely (e.g. Mode 0 Exploiter reading `kernel_vmlinux_path`) but
   *   must NEVER include `etc` in their `omp_patch_state` calls. Violation
   *   is caught by orchestrator audit (state diff); spec
   *   `contract-load-detect-split.md` D7 escalates to physical
   *   enforcement (`patch_state` checks `context.agent`) if violations
   *   accumulate.
   *
   * **Naming convention:** keys are snake_case with a domain prefix
   * (e.g. `kernel_*` / `source_*` / `library_*` / `multi_*`). Values are
   * JSON-able (string / number / boolean / array / nested object). The
   * schema validates only that the key is a string — value shape is the
   * writer's responsibility, and readers must defensively cast.
   *
   * Added by `.omc/specs/contract-load-detect-split.md` (D7, 2026-05-24).
   */
  etc: z.record(z.string(), z.unknown()).optional(),

  /* ── Meta ──────────────────────────────────────────────────────────────── */

  created_at: IsoTimestampSchema,
  updated_at: IsoTimestampSchema,
})
export type ChallengeState = z.infer<typeof ChallengeStateSchema>

/**
 * Input required to seed a fresh ChallengeState. The loader
 * (`omp_load_challenge`) only knows `challenge_dir` (+ optional
 * `workspace_root`); binary / dockerfile / source identification belongs to
 * omp-setup Phase 0 (Detect) per
 * `.omc/specs/contract-load-detect-split.md` (D1, D2).
 *
 * `binary_input_path` / `dockerfile_path` / `source_present` / `source_paths`
 * are intentionally absent here — they are seeded later by the setup agent
 * via `omp_patch_state` once Phase 0 detect resolves them. Similarly
 * `binary_path` / `binary_sha256` describe the patched copy produced by the
 * setup agent in Phase 3 and cannot be known at load time.
 */
export interface InitialChallengeStateInput {
  challenge_dir: string
  /**
   * Absolute host path to the plugin's workspace mount source. Seeded into
   * `state.workspace_root` so downstream agents (Setup, Reverser, VH, SA,
   * Exploiter) can compute per-challenge container paths without inferring
   * the plugin root themselves.
   */
  workspace_root?: string
}

/**
 * Build a minimal valid ChallengeState for a fresh challenge. Use this from
 * `omp_load_challenge` when initializing `.omp/state.json` for the first
 * time.
 *
 * Seeds only `challenge_dir` (and optional `workspace_root`) — the loader
 * no longer touches binary / dockerfile / source fields per
 * `.omc/specs/contract-load-detect-split.md` (D1). Those are written by the
 * omp-setup agent in Phase 0 (Detect) via `omp_patch_state`. The patched-
 * copy fields (`binary_path`, `binary_sha256`) remain undefined until the
 * setup agent populates them in Phase 3.
 */
export function createInitialChallengeState(
  input: InitialChallengeStateInput,
  now: Date = new Date(),
): ChallengeState {
  const timestamp = now.toISOString()
  return ChallengeStateSchema.parse({
    schema_version: CHALLENGE_STATE_SCHEMA_VERSION,
    challenge_dir: input.challenge_dir,
    ...(input.workspace_root !== undefined
      ? { workspace_root: input.workspace_root }
      : {}),
    created_at: timestamp,
    updated_at: timestamp,
  })
}
