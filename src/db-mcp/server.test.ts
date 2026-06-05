import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js"
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"

import { closeDb, openDb, type OmpDatabase } from "../db"
import { ChallengeStateSchema } from "../state/challenge-state"
import { decomposeState, writeStateRow } from "./mapper"
import { createDbMcpServer } from "./server"

const CID = "/tmp/chal-server"
const TS = "2026-06-05T00:00:00.000Z"
const ORCH = { agent_id: "orchestrator" }

function tmpDbPath(): { dir: string; dbPath: string } {
  const dir = join(
    tmpdir(),
    `omp-dbmcp-srv-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  )
  mkdirSync(dir, { recursive: true })
  return { dir, dbPath: join(dir, "state.db") }
}

function parse(res: unknown): Record<string, unknown> {
  const r = res as CallToolResult
  const item = r.content[0]
  if (!item || item.type !== "text") throw new Error("expected text result")
  return JSON.parse(item.text)
}

describe("omp-db MCP server (end-to-end via InMemoryTransport)", () => {
  let dir: string
  let db: OmpDatabase
  let client: Client

  async function call(name: string, args: Record<string, unknown>) {
    return parse(await client.callTool({ name, arguments: args }))
  }

  beforeEach(async () => {
    const tmp = tmpDbPath()
    dir = tmp.dir
    db = openDb({ dbPath: tmp.dbPath })

    // Seed an initial state row out-of-band (no create_state tool by design).
    const seed = ChallengeStateSchema.parse({
      schema_version: "1",
      challenge_dir: CID,
      created_at: TS,
      updated_at: TS,
    })
    db.transaction((tx) => writeStateRow(tx, decomposeState(seed)))

    const server = createDbMcpServer(db)
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair()
    client = new Client({ name: "test", version: "1.0.0" })
    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ])
  })

  afterEach(async () => {
    await client.close()
    closeDb(db)
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true })
  })

  test("lists all 6 tools", async () => {
    const { tools } = await client.listTools()
    expect(tools.map((t) => t.name).sort()).toEqual([
      "create_candidate",
      "delete_candidate",
      "patch_candidate",
      "patch_state",
      "read_candidate",
      "read_state",
    ])
  })

  test("read_state returns the seeded state; unknown → state_not_found", async () => {
    const ok = await call("read_state", { challenge_id: CID })
    expect(ok.ok).toBe(true)
    expect((ok.state as { challenge_dir: string }).challenge_dir).toBe(CID)

    const miss = await call("read_state", { challenge_id: "/nope" })
    expect(miss.error).toBe("state_not_found")
  })

  test("patch_state updates a top-level field (orchestrator)", async () => {
    const res = await call("patch_state", {
      challenge_id: CID,
      patch: { pipeline_phase: "vh_ensemble", pipeline_cycle: 2 },
      ...ORCH,
    })
    expect(res.ok).toBe(true)
    const reread = await call("read_state", { challenge_id: CID })
    expect((reread.state as { pipeline_phase: string }).pipeline_phase).toBe(
      "vh_ensemble",
    )
  })

  test("ACL Layer 2 — write tools reject non-orchestrator", async () => {
    const deny = await call("patch_state", {
      challenge_id: CID,
      patch: { pipeline_phase: "idle" },
      agent_id: "vulnhunter",
    })
    expect(deny.error).toBe("acl_denied")

    const denyCreate = await call("create_candidate", {
      challenge_id: CID,
      candidate: { id: "x", primitive: "p" },
      agent_id: "exploiter",
    })
    expect(denyCreate.error).toBe("acl_denied")
  })

  test("patch_state vuln_candidates summary upsert surfaces in read_state", async () => {
    const res = await call("patch_state", {
      challenge_id: CID,
      patch: {
        vuln_candidates: [
          { id: "v1", primitive: "uaf", verification_result: "confirmed" },
        ],
      },
      ...ORCH,
    })
    expect(res.ok).toBe(true)
    const reread = await call("read_state", { challenge_id: CID })
    expect((reread.state as { vuln_candidates: unknown[] }).vuln_candidates).toEqual([
      { id: "v1", primitive: "uaf", verification_result: "confirmed" },
    ])
  })

  test("patch_state rejects detail fields in a vuln_candidates row", async () => {
    const res = await call("patch_state", {
      challenge_id: CID,
      patch: { vuln_candidates: [{ id: "v1", primitive: "uaf", rationale: "leak" }] },
      ...ORCH,
    })
    expect(res.error).toBe("vuln_candidates_detail_in_summary_patch")
    expect(res.leaked_fields).toEqual(["rationale"])
  })

  test("candidate lifecycle: create → read → patch → delete", async () => {
    const created = await call("create_candidate", {
      challenge_id: CID,
      candidate: {
        id: "v1",
        primitive: "tcache_poison",
        rationale: "why",
        gives: ["libc_base"],
      },
      ...ORCH,
    })
    expect(created.ok).toBe(true)

    const dup = await call("create_candidate", {
      challenge_id: CID,
      candidate: { id: "v1", primitive: "x" },
      ...ORCH,
    })
    expect(dup.error).toBe("duplicate_id")

    const read = await call("read_candidate", { challenge_id: CID, id: "v1" })
    expect((read.candidate as { rationale: string }).rationale).toBe("why")

    const patched = await call("patch_candidate", {
      challenge_id: CID,
      id: "v1",
      patch: { detail: { rationale: "updated", needs: ["heap"] } },
      ...ORCH,
    })
    expect((patched.candidate as { rationale: string }).rationale).toBe("updated")
    expect((patched.candidate as { needs: string[] }).needs).toEqual(["heap"])

    const del = await call("delete_candidate", { challenge_id: CID, id: "v1", ...ORCH })
    expect(del.ok).toBe(true)
    const gone = await call("read_candidate", { challenge_id: CID, id: "v1" })
    expect(gone.error).toBe("candidate_not_found")
  })

  test("create_candidate rejects when state row is absent", async () => {
    const res = await call("create_candidate", {
      challenge_id: "/no-state",
      candidate: { id: "v1", primitive: "p" },
      ...ORCH,
    })
    expect(res.error).toBe("state_not_found")
  })
})
