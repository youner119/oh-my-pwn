import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { challenges, closeDb, openDb, type OmpDatabase } from "../db"
import {
  ChallengeStateSchema,
  VulnCandidateSchema,
  type ChallengeState,
  type VulnCandidate,
} from "../state/challenge-state"
import {
  decomposeCandidate,
  decomposeState,
  deleteCandidateRow,
  deriveCategory,
  insertCandidate,
  loadCandidate,
  loadState,
  upsertCandidateSummary,
  writeStateRow,
} from "./mapper"

describe("deriveCategory", () => {
  test("user-mode-elf maps to itself", () => {
    expect(deriveCategory("user-mode-elf", null)).toBe("user-mode-elf")
  })
  test("unsupported uses unsupported_kind, else 'unsupported'", () => {
    expect(deriveCategory("unsupported", "kernel-pwn")).toBe("kernel-pwn")
    expect(deriveCategory("unsupported", null)).toBe("unsupported")
  })
  test("not-yet-classified → 'unclassified'", () => {
    expect(deriveCategory(null, null)).toBe("unclassified")
    expect(deriveCategory(undefined, undefined)).toBe("unclassified")
  })
})

const CID = "chalmapper_aaaa0001" // surrogate challenge_id (the key)
const DIR = "/tmp/chal-mapper" // challenge_dir (lives in challenges.dir)
const TS = "2026-06-05T00:00:00.000Z"

function tmpDbPath(label: string): { dir: string; dbPath: string } {
  const dir = join(
    tmpdir(),
    `omp-dbmcp-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  )
  mkdirSync(dir, { recursive: true })
  return { dir, dbPath: join(dir, "state.db") }
}

function seedState(db: OmpDatabase, state: ChallengeState): void {
  db.insert(challenges)
    .values({
      challengeId: CID,
      name: "m",
      dir: state.challenge_dir,
      createdAt: TS,
      updatedAt: TS,
    })
    .onConflictDoNothing()
    .run()
  const decomp = decomposeState(CID, state)
  db.transaction((tx) => writeStateRow(tx, decomp))
}

function seedCandidate(db: OmpDatabase, cid: string, c: VulnCandidate): void {
  const decomp = decomposeCandidate(cid, c)
  db.transaction((tx) => insertCandidate(tx, decomp))
}

describe("mapper round-trips", () => {
  let dir: string
  let db: OmpDatabase

  beforeEach(() => {
    const tmp = tmpDbPath("rt")
    dir = tmp.dir
    db = openDb({ dbPath: tmp.dbPath })
  })
  afterEach(() => {
    closeDb(db)
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true })
  })

  test("state decompose → write → reassemble preserves a rich ChallengeState", async () => {
    const state = ChallengeStateSchema.parse({
      schema_version: "1",
      challenge_dir: DIR,
      binary_input_path: "/tmp/chal-mapper/prob",
      source_present: true,
      source_paths: ["/tmp/chal-mapper/a.c", "/tmp/chal-mapper/b.c"],
      workspace_root: "/ws",
      challenge_type: "user-mode-elf",
      setup_complete: true,
      libc_version: "2.39",
      libc_path: "/x/libc.so.6",
      ld_path: "/x/ld.so",
      extracted_libs: { "libc.so.6": "/x/libc.so.6", "ld-linux-x86-64.so.2": "/x/ld.so" },
      docker_image: "img:1",
      mitigations: { nx: true, pie: true, canary: false, relro: "full", seccomp: false, cet: { ibt_marked: true, shstk_marked: true, enforced: false } },
      remote: { host: "1.2.3.4", port: 1337, wrapper: "ynetd", command: "./prob" },
      parallel_config: { vh_instance_count: 8, sa_instance_count: 6, max_cycles: 12, max_retries_per_candidate: 2 },
      pipeline_phase: "vh_ensemble",
      pipeline_cycle: 3,
      setup_blocker: {
        kind: "ambiguous-binary",
        candidates: ["/tmp/chal-mapper/a", "/tmp/chal-mapper/b"],
        message: "two ELFs",
      },
      corrections: [{ timestamp: TS, user_text: "fix libc", applied_delta: "libc_version=2.39" }],
      etc: { kernel_kaslr: true, binary_roles: { server: "/s" } },
      created_at: TS,
      updated_at: TS,
    })

    seedState(db, state)
    const loaded = await loadState(db, CID)
    expect(loaded).toEqual(state)
  })

  test("cet marked-but-unmeasured (enforced:null) round-trips", async () => {
    const state = ChallengeStateSchema.parse({
      schema_version: "1",
      challenge_dir: DIR,
      // Phase 1 records the marking; enforced stays null until Phase 5 measures it.
      mitigations: { nx: true, cet: { ibt_marked: true, shstk_marked: true, enforced: null } },
      created_at: TS,
      updated_at: TS,
    })
    seedState(db, state)
    const loaded = await loadState(db, CID)
    expect(loaded?.mitigations?.cet).toEqual({
      ibt_marked: true,
      shstk_marked: true,
      enforced: null,
    })
  })

  test("candidate decompose → insert → reassemble preserves full VulnCandidate", async () => {
    const minimal = ChallengeStateSchema.parse({
      schema_version: "1",
      challenge_dir: DIR,
      created_at: TS,
      updated_at: TS,
    })
    seedState(db, minimal)

    const cand = VulnCandidateSchema.parse({
      id: "vuln_1",
      primitive: "tcache_poison",
      verification_result: "confirmed",
      agent: "VH-3",
      combined_from: ["vuln_a", "vuln_b"],
      description: "small-bin overlap",
      gives_count: 2,
      needs_count: 1,
      has_poc: true,
      location: "main+0x40",
      confidence: 0.8,
      rationale: "double free into __free_hook",
      libc_range: "2.31-2.35",
      origin_type: "derived",
      derived_from: "vuln_a",
      poc_script_path: "/p/poc.py",
      gives: ["rip_control", "arbitrary_write"],
      needs: ["libc_base"],
      verification_blockers: [
        { cause: "PIE base mismatch", suggested_fix: "translate", retry_recommended: true },
      ],
    })

    seedCandidate(db, CID, cand)
    const loaded = await loadCandidate(db, CID, "vuln_1")
    expect(loaded).toEqual(cand)
  })

  test("read_state projects candidate rows down to vuln_candidates summaries", async () => {
    const minimal = ChallengeStateSchema.parse({
      schema_version: "1",
      challenge_dir: DIR,
      created_at: TS,
      updated_at: TS,
    })
    seedState(db, minimal)
    seedCandidate(
      db,
      CID,
      VulnCandidateSchema.parse({
        id: "vuln_1",
        primitive: "uaf",
        verification_result: "confirmed",
        combined_from: ["x"],
        rationale: "detail-only — must NOT appear in summary",
        gives: ["rip_control"],
      }),
    )

    const state = await loadState(db, CID)
    expect(state?.vuln_candidates).toEqual([
      {
        id: "vuln_1",
        primitive: "uaf",
        verification_result: "confirmed",
        combined_from: ["x"],
      },
    ])
    // rationale/gives are detail → never surface in the summary projection.
    expect(JSON.stringify(state?.vuln_candidates)).not.toContain("rationale")
  })
})

describe("patch_state vuln_candidates = (a) semantics", () => {
  let dir: string
  let db: OmpDatabase

  beforeEach(() => {
    const tmp = tmpDbPath("a")
    dir = tmp.dir
    db = openDb({ dbPath: tmp.dbPath })
    seedState(
      db,
      ChallengeStateSchema.parse({
        schema_version: "1",
        challenge_dir: DIR,
        created_at: TS,
        updated_at: TS,
      }),
    )
  })
  afterEach(() => {
    closeDb(db)
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true })
  })

  test("summary upsert preserves detail columns + detail FK arrays", async () => {
    seedCandidate(
      db,
      CID,
      VulnCandidateSchema.parse({
        id: "vuln_1",
        primitive: "uaf",
        rationale: "full reasoning",
        gives: ["libc_base"],
        needs: ["heap_addr"],
        verification_blockers: [{ cause: "attach failed", retry_recommended: false }],
        poc_script_path: "/p.py",
      }),
    )

    db.transaction((tx) =>
      upsertCandidateSummary(tx, CID, {
        id: "vuln_1",
        primitive: "uaf_write",
        verification_result: "confirmed",
        has_poc: true,
      }),
    )

    const loaded = await loadCandidate(db, CID, "vuln_1")
    // summary columns updated (whole-object replace: agent was absent → stays absent)
    expect(loaded?.primitive).toBe("uaf_write")
    expect(loaded?.verification_result).toBe("confirmed")
    expect(loaded?.has_poc).toBe(true)
    // detail preserved
    expect(loaded?.rationale).toBe("full reasoning")
    expect(loaded?.gives).toEqual(["libc_base"])
    expect(loaded?.needs).toEqual(["heap_addr"])
    expect(loaded?.verification_blockers).toEqual([
      { cause: "attach failed", retry_recommended: false },
    ])
    expect(loaded?.poc_script_path).toBe("/p.py")
  })

  test("ids absent from a summary upsert are NOT deleted", async () => {
    seedCandidate(db, CID, VulnCandidateSchema.parse({ id: "vuln_1", primitive: "a" }))
    seedCandidate(db, CID, VulnCandidateSchema.parse({ id: "vuln_2", primitive: "b" }))

    db.transaction((tx) =>
      upsertCandidateSummary(tx, CID, { id: "vuln_1", primitive: "a2" }),
    )

    expect(await loadCandidate(db, CID, "vuln_1")).not.toBeNull()
    expect(await loadCandidate(db, CID, "vuln_2")).not.toBeNull()
    expect((await loadState(db, CID))?.vuln_candidates).toHaveLength(2)
  })

  test("summary upsert of a new id inserts a summary-only row", async () => {
    db.transaction((tx) =>
      upsertCandidateSummary(tx, CID, {
        id: "vuln_new",
        primitive: "stack_bof",
        verification_result: "inconclusive",
      }),
    )
    const loaded = await loadCandidate(db, CID, "vuln_new")
    expect(loaded?.primitive).toBe("stack_bof")
    expect(loaded?.verification_result).toBe("inconclusive")
    expect(loaded?.rationale).toBeUndefined()
  })

  test("delete removes the row and cascades FK arrays", async () => {
    seedCandidate(
      db,
      CID,
      VulnCandidateSchema.parse({ id: "vuln_1", primitive: "a", gives: ["x"] }),
    )
    const existed = db.transaction((tx) => deleteCandidateRow(tx, CID, "vuln_1"))
    expect(existed).toBe(true)
    expect(await loadCandidate(db, CID, "vuln_1")).toBeNull()
    const again = db.transaction((tx) => deleteCandidateRow(tx, CID, "vuln_1"))
    expect(again).toBe(false)
  })
})
