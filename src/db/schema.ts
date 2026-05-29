/**
 * Drizzle ORM schema for the per-challenge SQLite database
 * (`<challenge>/.omp/state.db`).
 *
 * Spec: `.omc/specs/deep-interview-database-mcp.md` (T1).
 *
 * Design rules (interview decisions):
 *
 * 1. **Hybrid normalization** (Round 7-9 — State schema 영역):
 *    - Top-level scalars + stable nested objects (mitigations / remote /
 *      parallel_config / setup_blocker) → column flatten.
 *    - Arrays (source_paths / setup_blocker_candidates / corrections /
 *      extracted_libs) → 별개 FK table (consistent — 사용자 결정 (a)).
 *    - `etc` (다양한 환경 dump — kernel / source-only / library / multi-binary)
 *      → JSON column (`etc_json`). 사용자 명시.
 *
 * 2. **Candidate merge** (Round 9 — Candidate schema 영역):
 *    - Summary + Detail → 한 table 박힘 (`candidates`). File 분리 동기 (size cap)
 *      가 SQLite column SELECT 박힘 영역에서 자연 해소.
 *    - Array (combined_from / gives / needs / verification_blockers) → 별개
 *      FK table 일관 (state 패턴 동일). cross-candidate query (gap 분석)
 *      자연 — `SELECT candidate_id FROM candidates_gives WHERE primitive='libc_base'`.
 *
 * 3. **`challenge_id` column 모든 table 박힘** (Round 9 — spec Soft Constraint):
 *    - Per-file DB 영역에서 redundant 하지만 future server DB row-level
 *      isolation ready + 명시적 audit + array table 영역에서 challenge_id
 *      직접 query 자연.
 *
 * 4. **MCP server typed handler 가 multi-table → single object 합침** —
 *    Drizzle relations + with (1 query LEFT JOIN preload). Agent 입장에서
 *    table 분리 영역 transparent. 받는 표현 = 현 `VulnCandidate` /
 *    `ChallengeState` 와 1:1 동일.
 *
 * Source enum / nested schema 영역 = `src/state/challenge-state.ts` 의 zod
 * schema 와 동기 박힘. Drizzle text({ enum }) 박힘 → zod enum 영역과 동등.
 */

import { relations } from "drizzle-orm"
import {
  foreignKey,
  integer,
  primaryKey,
  real,
  sqliteTable,
  text,
} from "drizzle-orm/sqlite-core"

// ──────────────────────────────────────────────────────────────────────────
// State table — 메인 row per challenge (PK = challenge_id)
// ──────────────────────────────────────────────────────────────────────────

export const state = sqliteTable("state", {
  /** PK — `<challenge>/.omp/state.db` 영역에서 보통 한 row, future global DB
   *  ready 영역에서 multi-row + isolation. */
  challengeId: text("challenge_id").primaryKey(),

  // ── Meta ──────────────────────────────────────────────────────────────
  schemaVersion: text("schema_version").notNull(),
  challengeDir: text("challenge_dir").notNull(),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),

  // ── Input contract (omp-setup Phase 0 Detect 박힘) ────────────────────
  binaryPath: text("binary_path"),
  binarySha256: text("binary_sha256"),
  binaryInputPath: text("binary_input_path"),
  binaryInputSha256: text("binary_input_sha256"),
  dockerfilePath: text("dockerfile_path"),
  sourcePresent: integer("source_present", { mode: "boolean" }).default(false),

  // ── Setup gate (omp-setup) ─────────────────────────────────────────────
  workspaceRoot: text("workspace_root"),
  challengeType: text("challenge_type", {
    enum: ["user-mode-elf", "unsupported"],
  }),
  setupComplete: integer("setup_complete", { mode: "boolean" }),
  setupUnsupportedReason: text("setup_unsupported_reason"),
  unsupportedKind: text("unsupported_kind", {
    enum: [
      "kernel-pwn",
      "arm-userland",
      "multi-binary",
      "browser",
      "library-only",
      "source-only",
      "other",
    ],
  }),
  challengeSummary: text("challenge_summary"),

  // ── SetupBlocker (flatten — array (candidates) 별개 table) ────────────
  setupBlockerKind: text("setup_blocker_kind", { enum: ["ambiguous-binary"] }),
  setupBlockerMessage: text("setup_blocker_message"),

  // ── Environment (Phase 1-5) ───────────────────────────────────────────
  libcVersion: text("libc_version"),
  libcPath: text("libc_path"),
  ldPath: text("ld_path"),
  dockerImage: text("docker_image"),

  // ── Mitigations (flatten 6 column) ────────────────────────────────────
  mitigationNx: integer("mitigation_nx", { mode: "boolean" }),
  mitigationPie: integer("mitigation_pie", { mode: "boolean" }),
  mitigationCanary: integer("mitigation_canary", { mode: "boolean" }),
  mitigationRelro: text("mitigation_relro"),
  mitigationSeccomp: integer("mitigation_seccomp", { mode: "boolean" }),
  mitigationRaw: text("mitigation_raw"),

  // ── RemoteEntrypoint (flatten 4 column) ───────────────────────────────
  remoteHost: text("remote_host"),
  remotePort: integer("remote_port"),
  remoteWrapper: text("remote_wrapper"),
  remoteCommand: text("remote_command"),

  // ── Reverser (T07) ────────────────────────────────────────────────────
  reverserSummaryPath: text("reverser_summary_path"),
  reverserResearchPath: text("reverser_research_path"),
  reverserResearchKoPath: text("reverser_research_ko_path"),
  pseudocodeDir: text("pseudocode_dir"),
  bndbPath: text("bndb_path"),
  reverserAnalyzedAt: text("reverser_analyzed_at"),

  // ── ParallelConfig (flatten 4 column) ─────────────────────────────────
  parallelVhInstanceCount: integer("parallel_vh_instance_count"),
  parallelSaInstanceCount: integer("parallel_sa_instance_count"),
  parallelMaxCycles: integer("parallel_max_cycles"),
  parallelMaxRetriesPerCandidate: integer("parallel_max_retries_per_candidate"),

  // ── Pipeline state ────────────────────────────────────────────────────
  pipelinePhase: text("pipeline_phase", {
    enum: ["idle", "vh_ensemble", "strategy_exploit", "cascading", "terminated"],
  }),
  pipelineCycle: integer("pipeline_cycle"),
  pipelineTerminationReason: text("pipeline_termination_reason", {
    enum: ["flag_found", "exhausted", "budget_exceeded", "user_intervention"],
  }),

  // ── etc — 다양 환경 dump (JSON serialized) ────────────────────────────
  /** Free-form record<string, unknown> serialized as JSON. 사용자 명시:
   *  "다양한 환경 — kernel / arm / dockerfile 없는 경우 등 — JSON 박힘".
   *  Write policy = state schema 의 etc 영역과 동일 (Orchestrator/Setup write,
   *  other agents read-only). */
  etcJson: text("etc_json"),
})

// ──────────────────────────────────────────────────────────────────────────
// State array FK tables (4 개)
// ──────────────────────────────────────────────────────────────────────────

export const stateSourcePaths = sqliteTable(
  "state_source_paths",
  {
    challengeId: text("challenge_id")
      .notNull()
      .references(() => state.challengeId, { onDelete: "cascade" }),
    ord: integer("ord").notNull(),
    path: text("path").notNull(),
  },
  (table) => [primaryKey({ columns: [table.challengeId, table.ord] })],
)

export const stateSetupBlockerCandidates = sqliteTable(
  "state_setup_blocker_candidates",
  {
    challengeId: text("challenge_id")
      .notNull()
      .references(() => state.challengeId, { onDelete: "cascade" }),
    ord: integer("ord").notNull(),
    path: text("path").notNull(),
  },
  (table) => [primaryKey({ columns: [table.challengeId, table.ord] })],
)

export const stateCorrections = sqliteTable(
  "state_corrections",
  {
    challengeId: text("challenge_id")
      .notNull()
      .references(() => state.challengeId, { onDelete: "cascade" }),
    ord: integer("ord").notNull(),
    timestamp: text("timestamp").notNull(),
    userText: text("user_text").notNull(),
    appliedDelta: text("applied_delta"),
  },
  (table) => [primaryKey({ columns: [table.challengeId, table.ord] })],
)

export const stateExtractedLibs = sqliteTable(
  "state_extracted_libs",
  {
    challengeId: text("challenge_id")
      .notNull()
      .references(() => state.challengeId, { onDelete: "cascade" }),
    /** SONAME / DT_NEEDED entry — `libc.so.6`, `ld-linux-x86-64.so.2`, etc. */
    soname: text("soname").notNull(),
    path: text("path").notNull(),
  },
  (table) => [primaryKey({ columns: [table.challengeId, table.soname] })],
)

// ──────────────────────────────────────────────────────────────────────────
// Candidates table — Summary + Detail merge (Round 9 (α) 박힘)
// ──────────────────────────────────────────────────────────────────────────

export const candidates = sqliteTable(
  "candidates",
  {
    id: text("id").notNull(),
    challengeId: text("challenge_id")
      .notNull()
      .references(() => state.challengeId, { onDelete: "cascade" }),

    // ── Summary scalars ─────────────────────────────────────────────────
    primitive: text("primitive").notNull(),
    verificationResult: text("verification_result", {
      enum: ["confirmed", "failed", "inconclusive"],
    }),
    agent: text("agent"),
    description: text("description"),
    /** Derived counters — Orchestrator syncs from FK arrays at patch time. */
    givesCount: integer("gives_count"),
    needsCount: integer("needs_count"),
    /** Boolean mirror of (poc_script_path !== null) for summary visibility. */
    hasPoc: integer("has_poc", { mode: "boolean" }),

    // ── Detail scalars ──────────────────────────────────────────────────
    location: text("location"),
    /** 0.0–1.0 float confidence from the hunter. */
    confidence: real("confidence"),
    rationale: text("rationale"),
    libcRange: text("libc_range"),
    originType: text("origin_type", {
      enum: ["initial", "derived", "incidental"],
    }),
    derivedFrom: text("derived_from"),
    pocScriptPath: text("poc_script_path"),
  },
  (table) => [
    primaryKey({ columns: [table.challengeId, table.id] }),
  ],
)

// ──────────────────────────────────────────────────────────────────────────
// Candidates array FK tables (4 개)
// ──────────────────────────────────────────────────────────────────────────

export const candidatesCombinedFrom = sqliteTable(
  "candidates_combined_from",
  {
    challengeId: text("challenge_id").notNull(),
    candidateId: text("candidate_id").notNull(),
    ord: integer("ord").notNull(),
    /** Source candidate id this entry merged/derived from. */
    sourceId: text("source_id").notNull(),
  },
  (table) => [
    primaryKey({
      columns: [table.challengeId, table.candidateId, table.ord],
    }),
    foreignKey({
      columns: [table.challengeId, table.candidateId],
      foreignColumns: [candidates.challengeId, candidates.id],
    }).onDelete("cascade"),
  ],
)

export const candidatesGives = sqliteTable(
  "candidates_gives",
  {
    challengeId: text("challenge_id").notNull(),
    candidateId: text("candidate_id").notNull(),
    ord: integer("ord").notNull(),
    /** Verified primitive name — `libc_base`, `arbitrary_write`, `rip_control`. */
    primitiveName: text("primitive_name").notNull(),
  },
  (table) => [
    primaryKey({
      columns: [table.challengeId, table.candidateId, table.ord],
    }),
    foreignKey({
      columns: [table.challengeId, table.candidateId],
      foreignColumns: [candidates.challengeId, candidates.id],
    }).onDelete("cascade"),
  ],
)

export const candidatesNeeds = sqliteTable(
  "candidates_needs",
  {
    challengeId: text("challenge_id").notNull(),
    candidateId: text("candidate_id").notNull(),
    ord: integer("ord").notNull(),
    /** Required primitive name (must be `gives` of another verified candidate). */
    primitiveName: text("primitive_name").notNull(),
  },
  (table) => [
    primaryKey({
      columns: [table.challengeId, table.candidateId, table.ord],
    }),
    foreignKey({
      columns: [table.challengeId, table.candidateId],
      foreignColumns: [candidates.challengeId, candidates.id],
    }).onDelete("cascade"),
  ],
)

export const candidatesVerificationBlockers = sqliteTable(
  "candidates_verification_blockers",
  {
    challengeId: text("challenge_id").notNull(),
    candidateId: text("candidate_id").notNull(),
    ord: integer("ord").notNull(),
    /** Methodology blocker (PIE base translation needed, GDB attach failed, ...). */
    cause: text("cause").notNull(),
    suggestedFix: text("suggested_fix"),
    retryRecommended: integer("retry_recommended", { mode: "boolean" })
      .notNull()
      .default(false),
  },
  (table) => [
    primaryKey({
      columns: [table.challengeId, table.candidateId, table.ord],
    }),
    foreignKey({
      columns: [table.challengeId, table.candidateId],
      foreignColumns: [candidates.challengeId, candidates.id],
    }).onDelete("cascade"),
  ],
)

// ──────────────────────────────────────────────────────────────────────────
// Drizzle relations — MCP handler 박힘 영역에서 `with: { ... }` preload
// (1 query LEFT JOIN, N+1 회피).
// ──────────────────────────────────────────────────────────────────────────

export const stateRelations = relations(state, ({ many }) => ({
  sourcePaths: many(stateSourcePaths),
  setupBlockerCandidates: many(stateSetupBlockerCandidates),
  corrections: many(stateCorrections),
  extractedLibs: many(stateExtractedLibs),
  candidates: many(candidates),
}))

export const stateSourcePathsRelations = relations(
  stateSourcePaths,
  ({ one }) => ({
    state: one(state, {
      fields: [stateSourcePaths.challengeId],
      references: [state.challengeId],
    }),
  }),
)

export const stateSetupBlockerCandidatesRelations = relations(
  stateSetupBlockerCandidates,
  ({ one }) => ({
    state: one(state, {
      fields: [stateSetupBlockerCandidates.challengeId],
      references: [state.challengeId],
    }),
  }),
)

export const stateCorrectionsRelations = relations(
  stateCorrections,
  ({ one }) => ({
    state: one(state, {
      fields: [stateCorrections.challengeId],
      references: [state.challengeId],
    }),
  }),
)

export const stateExtractedLibsRelations = relations(
  stateExtractedLibs,
  ({ one }) => ({
    state: one(state, {
      fields: [stateExtractedLibs.challengeId],
      references: [state.challengeId],
    }),
  }),
)

export const candidatesRelations = relations(candidates, ({ many, one }) => ({
  state: one(state, {
    fields: [candidates.challengeId],
    references: [state.challengeId],
  }),
  combinedFrom: many(candidatesCombinedFrom),
  gives: many(candidatesGives),
  needs: many(candidatesNeeds),
  verificationBlockers: many(candidatesVerificationBlockers),
}))

export const candidatesCombinedFromRelations = relations(
  candidatesCombinedFrom,
  ({ one }) => ({
    candidate: one(candidates, {
      fields: [
        candidatesCombinedFrom.challengeId,
        candidatesCombinedFrom.candidateId,
      ],
      references: [candidates.challengeId, candidates.id],
    }),
  }),
)

export const candidatesGivesRelations = relations(
  candidatesGives,
  ({ one }) => ({
    candidate: one(candidates, {
      fields: [candidatesGives.challengeId, candidatesGives.candidateId],
      references: [candidates.challengeId, candidates.id],
    }),
  }),
)

export const candidatesNeedsRelations = relations(
  candidatesNeeds,
  ({ one }) => ({
    candidate: one(candidates, {
      fields: [candidatesNeeds.challengeId, candidatesNeeds.candidateId],
      references: [candidates.challengeId, candidates.id],
    }),
  }),
)

export const candidatesVerificationBlockersRelations = relations(
  candidatesVerificationBlockers,
  ({ one }) => ({
    candidate: one(candidates, {
      fields: [
        candidatesVerificationBlockers.challengeId,
        candidatesVerificationBlockers.candidateId,
      ],
      references: [candidates.challengeId, candidates.id],
    }),
  }),
)

// ──────────────────────────────────────────────────────────────────────────
// Type exports — Drizzle 의 inferSelect / inferInsert 박힘
// (T2+ 박힐 영역에서 사용 — MCP handler 가 zod schema 박은 객체 박힌 후 변환)
// ──────────────────────────────────────────────────────────────────────────

export type StateRow = typeof state.$inferSelect
export type StateInsert = typeof state.$inferInsert
export type CandidatesRow = typeof candidates.$inferSelect
export type CandidatesInsert = typeof candidates.$inferInsert
