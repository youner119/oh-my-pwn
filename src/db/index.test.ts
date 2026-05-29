import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { sql } from "drizzle-orm"

import { closeDb, openDb, state, candidates, candidatesGives } from "./index"

function makeTmpDbPath(label: string): { dir: string; dbPath: string } {
  const dir = join(
    tmpdir(),
    `omp-db-test-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  )
  mkdirSync(dir, { recursive: true })
  return { dir, dbPath: join(dir, "state.db") }
}

describe("openDb", () => {
  let tmpDir: string
  let dbPath: string

  beforeEach(() => {
    const tmp = makeTmpDbPath("open")
    tmpDir = tmp.dir
    dbPath = tmp.dbPath
  })

  afterEach(() => {
    if (existsSync(tmpDir)) {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test("creates all 10 tables on first open", () => {
    const db = openDb({ dbPath })

    // Query SQLite's catalog for the user-defined tables.
    const rows = db.all<{ name: string }>(
      sql`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '__drizzle%' ORDER BY name`,
    )
    const tableNames = rows.map((r) => r.name)

    expect(tableNames).toEqual([
      "candidates",
      "candidates_combined_from",
      "candidates_gives",
      "candidates_needs",
      "candidates_verification_blockers",
      "state",
      "state_corrections",
      "state_extracted_libs",
      "state_setup_blocker_candidates",
      "state_source_paths",
    ])

    closeDb(db)
  })

  test("applies WAL journal_mode pragma", () => {
    const db = openDb({ dbPath })

    const rows = db.all<{ journal_mode: string }>(sql`PRAGMA journal_mode`)
    expect(rows[0]?.journal_mode).toBe("wal")

    closeDb(db)
  })

  test("applies foreign_keys = ON pragma", () => {
    const db = openDb({ dbPath })

    const rows = db.all<{ foreign_keys: number }>(sql`PRAGMA foreign_keys`)
    expect(rows[0]?.foreign_keys).toBe(1)

    closeDb(db)
  })

  test("is idempotent — second open on same db is a noop migration", () => {
    const db1 = openDb({ dbPath })
    closeDb(db1)

    // Should not throw, should not duplicate tables.
    const db2 = openDb({ dbPath })

    const rows = db2.all<{ name: string }>(
      sql`SELECT name FROM sqlite_master WHERE type='table' AND name='state'`,
    )
    expect(rows).toHaveLength(1)

    closeDb(db2)
  })

  test("enforces composite FK cascade — state delete removes candidates and array FKs", async () => {
    const db = openDb({ dbPath })

    const now = new Date().toISOString()
    await db.insert(state).values({
      challengeId: "test-1",
      schemaVersion: "1",
      challengeDir: "/tmp/test-1",
      createdAt: now,
      updatedAt: now,
    })
    await db.insert(candidates).values({
      challengeId: "test-1",
      id: "vuln_a",
      primitive: "stack_bof",
    })
    await db.insert(candidatesGives).values({
      challengeId: "test-1",
      candidateId: "vuln_a",
      ord: 0,
      primitiveName: "rip_control",
    })

    // Delete state row → should cascade to candidates → cascade to
    // candidates_gives.
    await db.delete(state).where(sql`challenge_id = 'test-1'`)

    const candCount = db.all<{ c: number }>(
      sql`SELECT COUNT(*) as c FROM candidates WHERE challenge_id = 'test-1'`,
    )
    expect(candCount[0]?.c).toBe(0)

    const givesCount = db.all<{ c: number }>(
      sql`SELECT COUNT(*) as c FROM candidates_gives WHERE challenge_id = 'test-1'`,
    )
    expect(givesCount[0]?.c).toBe(0)

    closeDb(db)
  })

  test("Drizzle relations preload — candidates with all array FKs in one query", async () => {
    const db = openDb({ dbPath })

    const now = new Date().toISOString()
    await db.insert(state).values({
      challengeId: "test-2",
      schemaVersion: "1",
      challengeDir: "/tmp/test-2",
      createdAt: now,
      updatedAt: now,
    })
    await db.insert(candidates).values({
      challengeId: "test-2",
      id: "vuln_b",
      primitive: "tcache_poison",
      description: "small-bin overlap into __free_hook",
    })
    await db.insert(candidatesGives).values([
      { challengeId: "test-2", candidateId: "vuln_b", ord: 0, primitiveName: "rip_control" },
      { challengeId: "test-2", candidateId: "vuln_b", ord: 1, primitiveName: "arbitrary_write" },
    ])

    const result = await db.query.candidates.findFirst({
      where: (c, { and, eq }) => and(eq(c.challengeId, "test-2"), eq(c.id, "vuln_b")),
      with: {
        gives: { orderBy: (g, { asc }) => asc(g.ord) },
        needs: true,
        combinedFrom: true,
        verificationBlockers: true,
      },
    })

    expect(result).toBeDefined()
    expect(result?.primitive).toBe("tcache_poison")
    expect(result?.gives).toHaveLength(2)
    expect(result?.gives[0]?.primitiveName).toBe("rip_control")
    expect(result?.gives[1]?.primitiveName).toBe("arbitrary_write")
    expect(result?.needs).toHaveLength(0)
    expect(result?.combinedFrom).toHaveLength(0)
    expect(result?.verificationBlockers).toHaveLength(0)

    closeDb(db)
  })
})
