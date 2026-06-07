import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js"
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"

import { challenges, closeDb, openDb, type OmpDatabase } from "../db"
import { ChallengeStateSchema } from "../state/challenge-state"
import { decomposeState, writeStateRow } from "./mapper"
import { createDbMcpServer } from "./server"

const CID = "chalserver_bbbb0001" // surrogate challenge_id (the key)
const DIR = "/tmp/chal-server" // challenge_dir (lives in challenges.dir)
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
      challenge_dir: DIR,
      created_at: TS,
      updated_at: TS,
    })
    db.insert(challenges)
      .values({ challengeId: CID, name: "s", dir: DIR, createdAt: TS, updatedAt: TS })
      .run()
    db.transaction((tx) => writeStateRow(tx, decomposeState(CID, seed)))

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

  test("lists all 11 tools", async () => {
    const { tools } = await client.listTools()
    expect(tools.map((t) => t.name).sort()).toEqual([
      "create_candidate",
      "delete_candidate",
      "delete_challenge",
      "lookup_challenge",
      "patch_candidate",
      "patch_state",
      "read_candidate",
      "read_challenge",
      "read_state",
      "register_challenge",
      "update_challenge",
    ])
  })

  test("register_challenge mints '<name>_<uuid8>'; duplicate dir → challenge_exists", async () => {
    const r1 = await call("register_challenge", {
      dir: "/tmp/chal-reg",
      name: "After Image!",
      ...ORCH,
    })
    expect(r1.ok).toBe(true)
    const id = r1.challenge_id as string
    expect(id).toMatch(/^after-image_[0-9a-f]{8}$/)
    expect((r1.challenge as { category: string }).category).toBe("unclassified")
    expect((r1.challenge as { status: string }).status).toBe("unsolved")

    // pure create: same dir → challenge_exists, no new row, original id returned
    const r2 = await call("register_challenge", { dir: "/tmp/chal-reg", ...ORCH })
    expect(r2.error).toBe("challenge_exists")
    expect(r2.challenge_id).toBe(id)

    // initial state row exists (read_state works on the minted id)
    const st = await call("read_state", { challenge_id: id })
    expect(st.ok).toBe(true)
    expect((st.state as { challenge_dir: string }).challenge_dir).toBe("/tmp/chal-reg")
  })

  test("lookup_challenge resolves dir→id; unknown dir → found:false", async () => {
    const reg = await call("register_challenge", { dir: "/tmp/chal-look", ...ORCH })
    const id = reg.challenge_id as string

    const hit = await call("lookup_challenge", { dir: "/tmp/chal-look" })
    expect(hit.ok).toBe(true)
    expect(hit.found).toBe(true)
    expect(hit.challenge_id).toBe(id)

    const miss = await call("lookup_challenge", { dir: "/tmp/never-registered" })
    expect(miss.ok).toBe(true)
    expect(miss.found).toBe(false)
  })

  test("register_challenge allows orchestrator + setup; denies others", async () => {
    const deny = await call("register_challenge", {
      dir: "/tmp/chal-x",
      agent_id: "vulnhunter",
    })
    expect(deny.error).toBe("acl_denied")

    const ok = await call("register_challenge", {
      dir: "/tmp/chal-setup",
      agent_id: "setup",
    })
    expect(ok.ok).toBe(true)
    expect(ok.challenge_id).toMatch(/^chal-setup_[0-9a-f]{8}$/)
  })

  test("read_challenge returns catalog; category derives from state classification", async () => {
    const reg = await call("register_challenge", { dir: "/tmp/chal-cat", ...ORCH })
    const id = reg.challenge_id as string

    const miss = await call("read_challenge", { challenge_id: "nope_00000000" })
    expect(miss.error).toBe("challenge_not_found")

    // classify via patch_state → category reflects it
    await call("patch_state", {
      challenge_id: id,
      patch: { challenge_type: "unsupported", unsupported_kind: "kernel-pwn" },
      ...ORCH,
    })
    const rc = await call("read_challenge", { challenge_id: id })
    expect((rc.challenge as { category: string }).category).toBe("kernel-pwn")
  })

  test("update_challenge sets status/notes; orchestrator-only", async () => {
    const reg = await call("register_challenge", { dir: "/tmp/chal-upd", ...ORCH })
    const id = reg.challenge_id as string

    const deny = await call("update_challenge", {
      challenge_id: id,
      patch: { status: "solved" },
      agent_id: "exploiter",
    })
    expect(deny.error).toBe("acl_denied")

    const upd = await call("update_challenge", {
      challenge_id: id,
      patch: { status: "solved", solved_at: "2026-06-05T12:00:00.000Z", notes: "fsop" },
      ...ORCH,
    })
    expect((upd.challenge as { status: string }).status).toBe("solved")
    expect((upd.challenge as { notes: string }).notes).toBe("fsop")
    expect((upd.challenge as { solved_at: string }).solved_at).toBe("2026-06-05T12:00:00.000Z")

    const gone = await call("update_challenge", {
      challenge_id: "missing_00000000",
      patch: { status: "solved" },
      ...ORCH,
    })
    expect(gone.error).toBe("challenge_not_found")
  })

  test("delete_challenge cascades state + candidates; orchestrator-only", async () => {
    const reg = await call("register_challenge", { dir: "/tmp/chal-del", ...ORCH })
    const id = reg.challenge_id as string

    // seed a candidate so the cascade count is observable
    const c = await call("create_candidate", {
      challenge_id: id,
      candidate: { id: "v1", primitive: "fmt_string_write", gives: ["aaw"] },
      ...ORCH,
    })
    expect(c.ok).toBe(true)

    // ACL: stricter than register — even setup is denied (orchestrator-only)
    const deny = await call("delete_challenge", { challenge_id: id, agent_id: "setup" })
    expect(deny.error).toBe("acl_denied")

    // delete cascades: catalog + state + candidate all gone
    const del = await call("delete_challenge", { challenge_id: id, ...ORCH })
    expect(del.ok).toBe(true)
    expect((del.deleted as { candidates_removed: number }).candidates_removed).toBe(1)

    expect((await call("read_challenge", { challenge_id: id })).error).toBe(
      "challenge_not_found",
    )
    expect((await call("read_state", { challenge_id: id })).error).toBe("state_not_found")

    // not found → challenge_not_found
    const missing = await call("delete_challenge", {
      challenge_id: "missing_00000000",
      ...ORCH,
    })
    expect(missing.error).toBe("challenge_not_found")
  })

  test("read_state returns the seeded state; unknown → state_not_found", async () => {
    const ok = await call("read_state", { challenge_id: CID })
    expect(ok.ok).toBe(true)
    expect((ok.state as { challenge_dir: string }).challenge_dir).toBe(DIR)

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

  test("ACL Layer 2 — patch_state allows setup + reverser; candidate writes don't", async () => {
    for (const id of ["setup", "reverser"]) {
      const ok = await call("patch_state", {
        challenge_id: CID,
        patch: { pipeline_phase: "idle" },
        agent_id: id,
      })
      expect(ok.ok).toBe(true)
    }
    // but they may NOT create candidates
    const deny = await call("create_candidate", {
      challenge_id: CID,
      candidate: { id: "c1", primitive: "p" },
      agent_id: "setup",
    })
    expect(deny.error).toBe("acl_denied")
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
