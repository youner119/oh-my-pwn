/**
 * Mapper layer for the omp-db MCP server.
 *
 * Spec: `.omc/specs/deep-interview-database-mcp.md` (T4/T5).
 *
 * The DB MCP tools speak the **old nested JSON shape** (`ChallengeState` /
 * `VulnCandidate`) so agent prompts change only the tool *name*, not the call
 * *meaning* (AC3). This module is the seam that reassembles the normalized 10
 * tables into those nested objects on read, and decomposes them back into rows
 * on write.
 *
 * Design notes (locked decisions, 2026-06-05):
 *
 * - **Summary + Detail = one `candidates` table** (T1 schema rule 2). The
 *   file-era split (state.json summary array + `candidates/<id>.json` detail)
 *   collapses to one row. The *tool* split (`patch_state` = summary channel,
 *   `patch_candidate` = detail channel) is kept intentionally — it reflects
 *   write *intent* (status vs evidence), not storage. The summary/detail field
 *   partition lives here as `SUMMARY_*` / detail column groups.
 *
 * - **`patch_state({ vuln_candidates })` semantics = (a)** — summary-column
 *   UPSERT preserving detail columns; ids absent from the array are left
 *   untouched (NOT deleted — deletion is `delete_candidate`'s job). See
 *   {@link upsertCandidateSummary}.
 *
 * - **Optional fields omit, never null.** Most `ChallengeState` /
 *   `VulnCandidate` fields are `z.…optional()` (reject `null`). Reassembly sets
 *   a field only when its column is non-null, so the parsed object matches what
 *   the file model produced.
 */

import { and, desc, eq } from "drizzle-orm"

import {
  ChallengeStateSchema,
  VulnCandidateSchema,
  VulnCandidateSummarySchema,
  VulnCandidateDetailSchema,
  createInitialChallengeState,
  type ChallengeState,
  type VulnCandidate,
  type VulnCandidateSummary,
} from "../state/challenge-state"
import {
  candidates,
  candidatesCombinedFrom,
  candidatesGives,
  candidatesNeeds,
  candidatesVerificationBlockers,
  challenges,
  state,
  stateCorrections,
  stateExtractedLibs,
  stateSetupBlockerCandidates,
  stateSourcePaths,
  type CandidatesInsert,
  type ChallengesInsert,
  type ChallengesRow,
  type OmpDatabase,
  type StateInsert,
} from "../db"

/**
 * Detail field names (auto-derived from the Detail schema). The `patch_state`
 * summary channel rejects any of these appearing in a `vuln_candidates[]` row
 * — that data belongs to `patch_candidate`. Same guard as the file-era
 * `omp_patch_state`.
 */
export const VULN_CANDIDATE_DETAIL_FIELDS = Object.keys(
  VulnCandidateDetailSchema.shape,
)

/** Transaction handle type — the callback arg of `db.transaction`. */
export type OmpTx = Parameters<Parameters<OmpDatabase["transaction"]>[0]>[0]

// ──────────────────────────────────────────────────────────────────────────
// State: decompose (ChallengeState → rows)
// ──────────────────────────────────────────────────────────────────────────

export interface StateDecomposition {
  row: StateInsert
  sourcePaths: { challengeId: string; ord: number; path: string }[]
  setupBlockerCandidates: { challengeId: string; ord: number; path: string }[]
  corrections: {
    challengeId: string
    ord: number
    timestamp: string
    userText: string
    appliedDelta: string | null
  }[]
  extractedLibs: { challengeId: string; soname: string; path: string }[]
}

/**
 * Decompose a (validated) `ChallengeState` into the `state` row + its four
 * array FK tables. `vuln_candidates` is intentionally ignored — candidate rows
 * are owned by the candidates table and managed via the candidate channel.
 *
 * `challengeId` is the surrogate `"<name>_<uuid8>"` (spec:
 * challenge-identity-catalog.md), passed explicitly — it is NOT
 * `s.challenge_dir` anymore (the dir lives in the `challenges` table and is
 * NOT written to the state row here).
 */
export function decomposeState(
  challengeId: string,
  s: ChallengeState,
): StateDecomposition {
  const cid = challengeId
  const m = s.mitigations
  const r = s.remote
  const pc = s.parallel_config
  const sb = s.setup_blocker

  const row: StateInsert = {
    challengeId: cid,
    schemaVersion: s.schema_version,
    createdAt: s.created_at,
    updatedAt: s.updated_at,
    binaryPath: s.binary_path ?? null,
    binarySha256: s.binary_sha256 ?? null,
    binaryInputPath: s.binary_input_path ?? null,
    binaryInputSha256: s.binary_input_sha256 ?? null,
    dockerfilePath: s.dockerfile_path ?? null,
    sourcePresent: s.source_present ?? false,
    workspaceRoot: s.workspace_root ?? null,
    challengeType: s.challenge_type ?? null,
    setupComplete: s.setup_complete ?? null,
    setupUnsupportedReason: s.setup_unsupported_reason ?? null,
    unsupportedKind: s.unsupported_kind ?? null,
    challengeSummary: s.challenge_summary ?? null,
    setupBlockerKind: sb?.kind ?? null,
    setupBlockerMessage: sb?.message ?? null,
    libcVersion: s.libc_version ?? null,
    libcPath: s.libc_path ?? null,
    ldPath: s.ld_path ?? null,
    dockerImage: s.docker_image ?? null,
    mitigationNx: m?.nx ?? null,
    mitigationPie: m?.pie ?? null,
    mitigationCanary: m?.canary ?? null,
    mitigationRelro: m?.relro ?? null,
    mitigationSeccomp: m?.seccomp ?? null,
    mitigationCetIbtMarked: m?.cet?.ibt_marked ?? null,
    mitigationCetShstkMarked: m?.cet?.shstk_marked ?? null,
    mitigationCetEnforced: m?.cet?.enforced ?? null,
    remoteHost: r?.host ?? null,
    remotePort: r?.port ?? null,
    remoteWrapper: r?.wrapper ?? null,
    remoteCommand: r?.command ?? null,
    reverserSummaryPath: s.reverser_summary_path ?? null,
    reverserResearchPath: s.reverser_research_path ?? null,
    reverserResearchKoPath: s.reverser_research_ko_path ?? null,
    pseudocodeDir: s.pseudocode_dir ?? null,
    bndbPath: s.bndb_path ?? null,
    reverserAnalyzedAt: s.reverser_analyzed_at ?? null,
    parallelVhInstanceCount: pc?.vh_instance_count ?? null,
    parallelSaInstanceCount: pc?.sa_instance_count ?? null,
    parallelMaxCycles: pc?.max_cycles ?? null,
    parallelMaxRetriesPerCandidate: pc?.max_retries_per_candidate ?? null,
    pipelinePhase: s.pipeline_phase ?? null,
    pipelineCycle: s.pipeline_cycle ?? null,
    pipelineTerminationReason: s.pipeline_termination_reason ?? null,
    etcJson: s.etc !== undefined ? JSON.stringify(s.etc) : null,
  }

  const sourcePaths = (s.source_paths ?? []).map((path, ord) => ({
    challengeId: cid,
    ord,
    path,
  }))
  const setupBlockerCandidates = (sb?.candidates ?? []).map((path, ord) => ({
    challengeId: cid,
    ord,
    path,
  }))
  const corrections = (s.corrections ?? []).map((c, ord) => ({
    challengeId: cid,
    ord,
    timestamp: c.timestamp,
    userText: c.user_text,
    appliedDelta: c.applied_delta ?? null,
  }))
  const extractedLibs = Object.entries(s.extracted_libs ?? {}).map(
    ([soname, path]) => ({ challengeId: cid, soname, path }),
  )

  return { row, sourcePaths, setupBlockerCandidates, corrections, extractedLibs }
}

// ──────────────────────────────────────────────────────────────────────────
// State: reassemble (rows → ChallengeState)
// ──────────────────────────────────────────────────────────────────────────

/** Shape of the relational query result used to rebuild a `ChallengeState`. */
export interface StateRelationalRow {
  challengeId: string
  schemaVersion: string
  /** Parent challenges row (preloaded via relation) — source of challenge_dir. */
  challenge: { dir: string }
  createdAt: string
  updatedAt: string
  binaryPath: string | null
  binarySha256: string | null
  binaryInputPath: string | null
  binaryInputSha256: string | null
  dockerfilePath: string | null
  sourcePresent: boolean | null
  workspaceRoot: string | null
  challengeType: ChallengeState["challenge_type"] | null
  setupComplete: boolean | null
  setupUnsupportedReason: string | null
  unsupportedKind: ChallengeState["unsupported_kind"] | null
  challengeSummary: string | null
  setupBlockerKind: "ambiguous-binary" | null
  setupBlockerMessage: string | null
  libcVersion: string | null
  libcPath: string | null
  ldPath: string | null
  dockerImage: string | null
  mitigationNx: boolean | null
  mitigationPie: boolean | null
  mitigationCanary: boolean | null
  mitigationRelro: string | null
  mitigationSeccomp: boolean | null
  mitigationCetIbtMarked: boolean | null
  mitigationCetShstkMarked: boolean | null
  mitigationCetEnforced: boolean | null
  remoteHost: string | null
  remotePort: number | null
  remoteWrapper: string | null
  remoteCommand: string | null
  reverserSummaryPath: string | null
  reverserResearchPath: string | null
  reverserResearchKoPath: string | null
  pseudocodeDir: string | null
  bndbPath: string | null
  reverserAnalyzedAt: string | null
  parallelVhInstanceCount: number | null
  parallelSaInstanceCount: number | null
  parallelMaxCycles: number | null
  parallelMaxRetriesPerCandidate: number | null
  pipelinePhase: ChallengeState["pipeline_phase"] | null
  pipelineCycle: number | null
  pipelineTerminationReason: ChallengeState["pipeline_termination_reason"] | null
  etcJson: string | null
  sourcePaths: { ord: number; path: string }[]
  setupBlockerCandidates: { ord: number; path: string }[]
  corrections: {
    ord: number
    timestamp: string
    userText: string
    appliedDelta: string | null
  }[]
  extractedLibs: { soname: string; path: string }[]
  candidates: CandidateRelationalRow[]
}

const byOrd = (a: { ord: number }, b: { ord: number }): number => a.ord - b.ord

/** Reassemble the nested `ChallengeState` from a relational row. */
export function reassembleState(row: StateRelationalRow): ChallengeState {
  const obj: Record<string, unknown> = {
    schema_version: row.schemaVersion,
    challenge_dir: row.challenge.dir,
    created_at: row.createdAt,
    updated_at: row.updatedAt,
    source_present: row.sourcePresent ?? false,
    source_paths: [...row.sourcePaths].sort(byOrd).map((p) => p.path),
    corrections: [...row.corrections].sort(byOrd).map((c) => ({
      timestamp: c.timestamp,
      user_text: c.userText,
      ...(c.appliedDelta != null ? { applied_delta: c.appliedDelta } : {}),
    })),
    vuln_candidates: row.candidates.map((c) =>
      candidateSummaryFromRow(c, c.combinedFrom),
    ),
  }

  const setStr = (
    key: string,
    v: string | number | boolean | null | undefined,
  ): void => {
    if (v != null) obj[key] = v
  }
  setStr("binary_path", row.binaryPath)
  setStr("binary_sha256", row.binarySha256)
  setStr("binary_input_path", row.binaryInputPath)
  setStr("binary_input_sha256", row.binaryInputSha256)
  setStr("dockerfile_path", row.dockerfilePath)
  setStr("workspace_root", row.workspaceRoot)
  setStr("challenge_type", row.challengeType)
  setStr("setup_complete", row.setupComplete)
  setStr("setup_unsupported_reason", row.setupUnsupportedReason)
  setStr("unsupported_kind", row.unsupportedKind)
  setStr("challenge_summary", row.challengeSummary)
  setStr("libc_version", row.libcVersion)
  setStr("libc_path", row.libcPath)
  setStr("ld_path", row.ldPath)
  setStr("docker_image", row.dockerImage)
  setStr("reverser_summary_path", row.reverserSummaryPath)
  setStr("reverser_research_path", row.reverserResearchPath)
  setStr("reverser_research_ko_path", row.reverserResearchKoPath)
  setStr("pseudocode_dir", row.pseudocodeDir)
  setStr("bndb_path", row.bndbPath)
  setStr("reverser_analyzed_at", row.reverserAnalyzedAt)
  setStr("pipeline_phase", row.pipelinePhase)
  setStr("pipeline_cycle", row.pipelineCycle)
  setStr("pipeline_termination_reason", row.pipelineTerminationReason)

  const mit: Record<string, unknown> = {}
  if (row.mitigationNx != null) mit.nx = row.mitigationNx
  if (row.mitigationPie != null) mit.pie = row.mitigationPie
  if (row.mitigationCanary != null) mit.canary = row.mitigationCanary
  if (row.mitigationRelro != null) mit.relro = row.mitigationRelro
  if (row.mitigationSeccomp != null) mit.seccomp = row.mitigationSeccomp
  // cet present iff the marking columns were written (enforced may be null)
  if (row.mitigationCetIbtMarked != null || row.mitigationCetShstkMarked != null) {
    mit.cet = {
      ibt_marked: row.mitigationCetIbtMarked ?? false,
      shstk_marked: row.mitigationCetShstkMarked ?? false,
      enforced: row.mitigationCetEnforced,
    }
  }
  if (Object.keys(mit).length > 0) obj.mitigations = mit

  // RemoteEntrypoint.host has a schema default ("127.0.0.1"); treat the block
  // as present if any remote column is non-null.
  if (
    row.remoteHost != null ||
    row.remotePort != null ||
    row.remoteWrapper != null ||
    row.remoteCommand != null
  ) {
    const rem: Record<string, unknown> = {}
    if (row.remoteHost != null) rem.host = row.remoteHost
    if (row.remotePort != null) rem.port = row.remotePort
    if (row.remoteWrapper != null) rem.wrapper = row.remoteWrapper
    if (row.remoteCommand != null) rem.command = row.remoteCommand
    obj.remote = rem
  }

  if (
    row.parallelVhInstanceCount != null ||
    row.parallelSaInstanceCount != null ||
    row.parallelMaxCycles != null ||
    row.parallelMaxRetriesPerCandidate != null
  ) {
    const p: Record<string, unknown> = {}
    if (row.parallelVhInstanceCount != null)
      p.vh_instance_count = row.parallelVhInstanceCount
    if (row.parallelSaInstanceCount != null)
      p.sa_instance_count = row.parallelSaInstanceCount
    if (row.parallelMaxCycles != null) p.max_cycles = row.parallelMaxCycles
    if (row.parallelMaxRetriesPerCandidate != null)
      p.max_retries_per_candidate = row.parallelMaxRetriesPerCandidate
    obj.parallel_config = p
  }

  if (row.setupBlockerKind != null) {
    obj.setup_blocker = {
      kind: row.setupBlockerKind,
      candidates: [...row.setupBlockerCandidates].sort(byOrd).map((c) => c.path),
      message: row.setupBlockerMessage ?? "",
    }
  }

  if (row.extractedLibs.length > 0) {
    obj.extracted_libs = Object.fromEntries(
      row.extractedLibs.map((l) => [l.soname, l.path]),
    )
  }

  if (row.etcJson != null) obj.etc = JSON.parse(row.etcJson)

  return ChallengeStateSchema.parse(obj)
}

// ──────────────────────────────────────────────────────────────────────────
// Candidate: decompose / reassemble
// ──────────────────────────────────────────────────────────────────────────

export interface CandidateRelationalRow {
  id: string
  primitive: string
  verificationResult: VulnCandidate["verification_result"] | null
  agent: string | null
  description: string | null
  givesCount: number | null
  needsCount: number | null
  hasPoc: boolean | null
  location: string | null
  confidence: number | null
  rationale: string | null
  libcRange: string | null
  originType: VulnCandidate["origin_type"] | null
  derivedFrom: string | null
  pocScriptPath: string | null
  combinedFrom: { ord: number; sourceId: string }[]
  gives: { ord: number; primitiveName: string }[]
  needs: { ord: number; primitiveName: string }[]
  verificationBlockers: {
    ord: number
    cause: string
    suggestedFix: string | null
    retryRecommended: boolean
  }[]
}

export interface CandidateDecomposition {
  row: CandidatesInsert
  combinedFrom: { challengeId: string; candidateId: string; ord: number; sourceId: string }[]
  gives: { challengeId: string; candidateId: string; ord: number; primitiveName: string }[]
  needs: { challengeId: string; candidateId: string; ord: number; primitiveName: string }[]
  verificationBlockers: {
    challengeId: string
    candidateId: string
    ord: number
    cause: string
    suggestedFix: string | null
    retryRecommended: boolean
  }[]
}

/** Decompose a (validated) `VulnCandidate` into row + four FK arrays. */
export function decomposeCandidate(
  cid: string,
  c: VulnCandidate,
): CandidateDecomposition {
  const row: CandidatesInsert = {
    challengeId: cid,
    id: c.id,
    primitive: c.primitive,
    verificationResult: c.verification_result ?? null,
    agent: c.agent ?? null,
    description: c.description ?? null,
    givesCount: c.gives_count ?? null,
    needsCount: c.needs_count ?? null,
    hasPoc: c.has_poc ?? null,
    location: c.location ?? null,
    confidence: c.confidence ?? null,
    rationale: c.rationale ?? null,
    libcRange: c.libc_range ?? null,
    originType: c.origin_type ?? null,
    derivedFrom: c.derived_from ?? null,
    pocScriptPath: c.poc_script_path ?? null,
  }
  return {
    row,
    combinedFrom: (c.combined_from ?? []).map((sourceId, ord) => ({
      challengeId: cid,
      candidateId: c.id,
      ord,
      sourceId,
    })),
    gives: (c.gives ?? []).map((primitiveName, ord) => ({
      challengeId: cid,
      candidateId: c.id,
      ord,
      primitiveName,
    })),
    needs: (c.needs ?? []).map((primitiveName, ord) => ({
      challengeId: cid,
      candidateId: c.id,
      ord,
      primitiveName,
    })),
    verificationBlockers: (c.verification_blockers ?? []).map((b, ord) => ({
      challengeId: cid,
      candidateId: c.id,
      ord,
      cause: b.cause,
      suggestedFix: b.suggested_fix ?? null,
      retryRecommended: b.retry_recommended ?? false,
    })),
  }
}

/** Reassemble a full (summary + detail) `VulnCandidate` from a relational row. */
export function reassembleCandidate(row: CandidateRelationalRow): VulnCandidate {
  const obj: Record<string, unknown> = {
    id: row.id,
    primitive: row.primitive,
  }
  const set = (
    key: string,
    v: string | number | boolean | null | undefined,
  ): void => {
    if (v != null) obj[key] = v
  }
  set("verification_result", row.verificationResult)
  set("agent", row.agent)
  set("description", row.description)
  set("gives_count", row.givesCount)
  set("needs_count", row.needsCount)
  set("has_poc", row.hasPoc)
  set("location", row.location)
  set("confidence", row.confidence)
  set("rationale", row.rationale)
  set("libc_range", row.libcRange)
  set("origin_type", row.originType)
  set("derived_from", row.derivedFrom)
  set("poc_script_path", row.pocScriptPath)

  if (row.combinedFrom.length > 0)
    obj.combined_from = [...row.combinedFrom].sort(byOrd).map((x) => x.sourceId)
  if (row.gives.length > 0)
    obj.gives = [...row.gives].sort(byOrd).map((x) => x.primitiveName)
  if (row.needs.length > 0)
    obj.needs = [...row.needs].sort(byOrd).map((x) => x.primitiveName)
  if (row.verificationBlockers.length > 0)
    obj.verification_blockers = [...row.verificationBlockers]
      .sort(byOrd)
      .map((b) => ({
        cause: b.cause,
        ...(b.suggestedFix != null ? { suggested_fix: b.suggestedFix } : {}),
        retry_recommended: b.retryRecommended,
      }))

  return VulnCandidateSchema.parse(obj)
}

/** Project a candidate row down to its summary fields (for `read_state`). */
export function candidateSummaryFromRow(
  row: Omit<CandidateRelationalRow, "gives" | "needs" | "verificationBlockers">,
  combinedFrom: { ord: number; sourceId: string }[],
): VulnCandidateSummary {
  const obj: Record<string, unknown> = {
    id: row.id,
    primitive: row.primitive,
  }
  const set = (
    key: string,
    v: string | number | boolean | null | undefined,
  ): void => {
    if (v != null) obj[key] = v
  }
  set("verification_result", row.verificationResult)
  set("agent", row.agent)
  set("description", row.description)
  set("gives_count", row.givesCount)
  set("needs_count", row.needsCount)
  set("has_poc", row.hasPoc)
  if (combinedFrom.length > 0)
    obj.combined_from = [...combinedFrom].sort(byOrd).map((x) => x.sourceId)
  return VulnCandidateSummarySchema.parse(obj)
}

// ──────────────────────────────────────────────────────────────────────────
// DB read helpers (relational queries — run outside transactions)
// ──────────────────────────────────────────────────────────────────────────

const STATE_WITH = {
  challenge: true,
  sourcePaths: true,
  setupBlockerCandidates: true,
  corrections: true,
  extractedLibs: true,
  candidates: {
    with: {
      combinedFrom: true,
      gives: true,
      needs: true,
      verificationBlockers: true,
    },
  },
} as const

/** Load + reassemble a `ChallengeState`. Returns `null` when the row is absent. */
export async function loadState(
  db: OmpDatabase,
  challengeId: string,
): Promise<ChallengeState | null> {
  const row = await db.query.state.findFirst({
    where: (s, { eq: e }) => e(s.challengeId, challengeId),
    with: STATE_WITH,
  })
  if (!row) return null
  return reassembleState(row as unknown as StateRelationalRow)
}

/** Whether a state row exists (cheap existence check for FK preconditions). */
export async function stateExists(
  db: OmpDatabase,
  challengeId: string,
): Promise<boolean> {
  const row = await db.query.state.findFirst({
    where: (s, { eq: e }) => e(s.challengeId, challengeId),
    columns: { challengeId: true },
  })
  return Boolean(row)
}

/** Load + reassemble one `VulnCandidate`. Returns `null` when absent. */
export async function loadCandidate(
  db: OmpDatabase,
  challengeId: string,
  id: string,
): Promise<VulnCandidate | null> {
  const row = await db.query.candidates.findFirst({
    where: (c, { and: a, eq: e }) =>
      a(e(c.challengeId, challengeId), e(c.id, id)),
    with: {
      combinedFrom: true,
      gives: true,
      needs: true,
      verificationBlockers: true,
    },
  })
  if (!row) return null
  return reassembleCandidate(row as unknown as CandidateRelationalRow)
}

// ──────────────────────────────────────────────────────────────────────────
// DB write helpers (sync — run inside db.transaction)
// ──────────────────────────────────────────────────────────────────────────

/** Build the `set` object for an upsert (all columns except the PK). */
function stateUpdateSet(row: StateInsert): Partial<StateInsert> {
  const { challengeId: _omit, ...rest } = row
  void _omit
  return rest
}

/**
 * Write the `state` row + its four array FK tables. Upserts the main row
 * (never deletes it — deletion would cascade to candidates) and replaces the
 * state-owned FK child rows wholesale. Candidates are NOT touched here.
 */
export function writeStateRow(tx: OmpTx, decomp: StateDecomposition): void {
  const cid = decomp.row.challengeId
  tx.insert(state)
    .values(decomp.row)
    .onConflictDoUpdate({ target: state.challengeId, set: stateUpdateSet(decomp.row) })
    .run()

  tx.delete(stateSourcePaths).where(eq(stateSourcePaths.challengeId, cid)).run()
  if (decomp.sourcePaths.length > 0)
    tx.insert(stateSourcePaths).values(decomp.sourcePaths).run()

  tx.delete(stateSetupBlockerCandidates)
    .where(eq(stateSetupBlockerCandidates.challengeId, cid))
    .run()
  if (decomp.setupBlockerCandidates.length > 0)
    tx.insert(stateSetupBlockerCandidates).values(decomp.setupBlockerCandidates).run()

  tx.delete(stateCorrections).where(eq(stateCorrections.challengeId, cid)).run()
  if (decomp.corrections.length > 0)
    tx.insert(stateCorrections).values(decomp.corrections).run()

  tx.delete(stateExtractedLibs).where(eq(stateExtractedLibs.challengeId, cid)).run()
  if (decomp.extractedLibs.length > 0)
    tx.insert(stateExtractedLibs).values(decomp.extractedLibs).run()
}

/** Replace all four candidate FK tables for one candidate. */
function replaceCandidateFks(tx: OmpTx, decomp: CandidateDecomposition): void {
  const cid = decomp.row.challengeId
  const id = decomp.row.id

  tx.delete(candidatesCombinedFrom)
    .where(
      and(
        eq(candidatesCombinedFrom.challengeId, cid),
        eq(candidatesCombinedFrom.candidateId, id),
      ),
    )
    .run()
  if (decomp.combinedFrom.length > 0)
    tx.insert(candidatesCombinedFrom).values(decomp.combinedFrom).run()

  tx.delete(candidatesGives)
    .where(and(eq(candidatesGives.challengeId, cid), eq(candidatesGives.candidateId, id)))
    .run()
  if (decomp.gives.length > 0) tx.insert(candidatesGives).values(decomp.gives).run()

  tx.delete(candidatesNeeds)
    .where(and(eq(candidatesNeeds.challengeId, cid), eq(candidatesNeeds.candidateId, id)))
    .run()
  if (decomp.needs.length > 0) tx.insert(candidatesNeeds).values(decomp.needs).run()

  tx.delete(candidatesVerificationBlockers)
    .where(
      and(
        eq(candidatesVerificationBlockers.challengeId, cid),
        eq(candidatesVerificationBlockers.candidateId, id),
      ),
    )
    .run()
  if (decomp.verificationBlockers.length > 0)
    tx.insert(candidatesVerificationBlockers).values(decomp.verificationBlockers).run()
}

/** Insert a brand-new candidate (row + FK). Caller checks duplicate first. */
export function insertCandidate(tx: OmpTx, decomp: CandidateDecomposition): void {
  tx.insert(candidates).values(decomp.row).run()
  replaceCandidateFks(tx, decomp)
}

/** Upsert a full candidate (row + FK) — used by `patch_candidate`. */
export function writeCandidate(tx: OmpTx, decomp: CandidateDecomposition): void {
  const { challengeId: _c, id: _i, ...set } = decomp.row
  void _c
  void _i
  tx.insert(candidates)
    .values(decomp.row)
    .onConflictDoUpdate({
      target: [candidates.challengeId, candidates.id],
      set,
    })
    .run()
  replaceCandidateFks(tx, decomp)
}

/**
 * `patch_state({ vuln_candidates })` semantics (a): UPSERT the summary columns
 * of one candidate, preserving every detail column + detail FK array. The
 * whole summary *object* is replaced (absent optional summary fields cleared to
 * null), matching the file model's whole-array-replace at the summary level —
 * but ids absent from the array are left alone (deletion = `delete_candidate`).
 *
 * `combined_from` is a summary field → its FK rows are replaced. `gives` /
 * `needs` / `verification_blockers` are detail → untouched.
 */
export function upsertCandidateSummary(
  tx: OmpTx,
  cid: string,
  summary: VulnCandidateSummary,
): void {
  const existing = tx
    .select({ id: candidates.id })
    .from(candidates)
    .where(and(eq(candidates.challengeId, cid), eq(candidates.id, summary.id)))
    .all()

  const summaryCols = {
    primitive: summary.primitive,
    verificationResult: summary.verification_result ?? null,
    agent: summary.agent ?? null,
    description: summary.description ?? null,
    givesCount: summary.gives_count ?? null,
    needsCount: summary.needs_count ?? null,
    hasPoc: summary.has_poc ?? null,
  }

  if (existing.length > 0) {
    tx.update(candidates)
      .set(summaryCols)
      .where(and(eq(candidates.challengeId, cid), eq(candidates.id, summary.id)))
      .run()
  } else {
    tx.insert(candidates)
      .values({ challengeId: cid, id: summary.id, ...summaryCols })
      .run()
  }

  // combined_from (summary FK) — replace wholesale.
  tx.delete(candidatesCombinedFrom)
    .where(
      and(
        eq(candidatesCombinedFrom.challengeId, cid),
        eq(candidatesCombinedFrom.candidateId, summary.id),
      ),
    )
    .run()
  const cf = summary.combined_from ?? []
  if (cf.length > 0)
    tx.insert(candidatesCombinedFrom)
      .values(
        cf.map((sourceId, ord) => ({
          challengeId: cid,
          candidateId: summary.id,
          ord,
          sourceId,
        })),
      )
      .run()
}

/** Delete a candidate row (FK rows cascade). Returns whether a row existed. */
export function deleteCandidateRow(
  tx: OmpTx,
  cid: string,
  id: string,
): boolean {
  const existing = tx
    .select({ id: candidates.id })
    .from(candidates)
    .where(and(eq(candidates.challengeId, cid), eq(candidates.id, id)))
    .all()
  if (existing.length === 0) return false
  tx.delete(candidates)
    .where(and(eq(candidates.challengeId, cid), eq(candidates.id, id)))
    .run()
  return true
}

// ──────────────────────────────────────────────────────────────────────────
// Challenge catalog (CI2) — register / read / update
// spec: challenge-identity-catalog.md (CI2)
// ──────────────────────────────────────────────────────────────────────────

/** Catalog view returned by register/read/update tools — challenges row + derived category. */
export interface ChallengeView {
  challenge_id: string
  name: string
  dir: string
  source: string | null
  status: string
  solved_at: string | null
  notes: string | null
  created_at: string
  updated_at: string
  /** Derived from state.challenge_type / unsupported_kind — NOT a stored column. */
  category: string
}

/**
 * Flat human-facing category derived from the setup classification (the single
 * source). `user-mode-elf` → itself; `unsupported` → the unsupported_kind (or
 * "unsupported"); not-yet-classified (setup未) → "unclassified".
 */
export function deriveCategory(
  challengeType: string | null | undefined,
  unsupportedKind: string | null | undefined,
): string {
  if (challengeType === "user-mode-elf") return "user-mode-elf"
  if (challengeType === "unsupported") return unsupportedKind ?? "unsupported"
  return "unclassified"
}

function challengeView(row: ChallengesRow, category: string): ChallengeView {
  return {
    challenge_id: row.challengeId,
    name: row.name,
    dir: row.dir,
    source: row.source ?? null,
    status: row.status,
    solved_at: row.solvedAt ?? null,
    notes: row.notes ?? null,
    created_at: row.createdAt,
    updated_at: row.updatedAt,
    category,
  }
}

/** Idempotency (i): most-recently-registered challenge at `dir`, or null. */
export async function findChallengeByDir(
  db: OmpDatabase,
  dir: string,
): Promise<ChallengesRow | null> {
  const rows = await db
    .select()
    .from(challenges)
    .where(eq(challenges.dir, dir))
    .orderBy(desc(challenges.createdAt))
    .limit(1)
  return rows[0] ?? null
}

/** Load a challenge's catalog view (challenges row + derived category). */
export async function loadChallengeView(
  db: OmpDatabase,
  challengeId: string,
): Promise<ChallengeView | null> {
  const ch = await db.query.challenges.findFirst({
    where: (c, { eq: e }) => e(c.challengeId, challengeId),
    with: { state: true },
  })
  if (!ch) return null
  const st = (ch as { state?: { challengeType: string | null; unsupportedKind: string | null } }).state
  return challengeView(ch, deriveCategory(st?.challengeType, st?.unsupportedKind))
}

/**
 * Register a new challenge: challenges row + an initial state row, atomically.
 * Caller has already generated `challengeId`/`name` and checked dir idempotency.
 */
export function insertChallengeWithState(
  db: OmpDatabase,
  args: {
    challengeId: string
    name: string
    dir: string
    workspaceRoot?: string
    now: Date
  },
): void {
  const { challengeId, name, dir, workspaceRoot, now } = args
  const iso = now.toISOString()
  const initial = createInitialChallengeState(
    {
      challenge_dir: dir,
      ...(workspaceRoot !== undefined ? { workspace_root: workspaceRoot } : {}),
    },
    now,
  )
  const decomp = decomposeState(challengeId, initial)
  db.transaction((tx) => {
    tx.insert(challenges)
      .values({
        challengeId,
        name,
        dir,
        status: "unsolved",
        createdAt: iso,
        updatedAt: iso,
      } satisfies ChallengesInsert)
      .run()
    writeStateRow(tx, decomp)
  })
}

/**
 * Update catalog fields (status / source / notes / solved_at). Only keys
 * present in `patch` are written; `updated_at` is stamped. Returns whether the
 * row existed.
 */
export function updateChallengeRow(
  db: OmpDatabase,
  challengeId: string,
  patch: {
    status?: string
    source?: string | null
    notes?: string | null
    solvedAt?: string | null
  },
  now: Date,
): boolean {
  const existing = db
    .select({ id: challenges.challengeId })
    .from(challenges)
    .where(eq(challenges.challengeId, challengeId))
    .all()
  if (existing.length === 0) return false

  const set: Partial<ChallengesInsert> = { updatedAt: now.toISOString() }
  if ("status" in patch) set.status = patch.status as ChallengesInsert["status"]
  if ("source" in patch) set.source = patch.source ?? null
  if ("notes" in patch) set.notes = patch.notes ?? null
  if ("solvedAt" in patch) set.solvedAt = patch.solvedAt ?? null

  db.update(challenges)
    .set(set)
    .where(eq(challenges.challengeId, challengeId))
    .run()
  return true
}

/**
 * Permanently delete a challenge. Removing the parent `challenges` row cascades
 * (ON DELETE CASCADE; the `foreign_keys` pragma is set in openDb) to the `state`
 * row, every `candidates` row, and all dependent FK-array tables. Returns
 * `{existed:false}` when no such challenge, else `{existed:true}` with the
 * candidate count removed (read before the delete).
 */
export function deleteChallengeRow(
  db: OmpDatabase,
  challengeId: string,
): { existed: boolean; candidatesRemoved: number } {
  const existing = db
    .select({ id: challenges.challengeId })
    .from(challenges)
    .where(eq(challenges.challengeId, challengeId))
    .all()
  if (existing.length === 0) return { existed: false, candidatesRemoved: 0 }

  const candidatesRemoved = db
    .select({ id: candidates.id })
    .from(candidates)
    .where(eq(candidates.challengeId, challengeId))
    .all().length

  db.delete(challenges).where(eq(challenges.challengeId, challengeId)).run()
  return { existed: true, candidatesRemoved }
}
