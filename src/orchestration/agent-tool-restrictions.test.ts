import { describe, expect, test } from "bun:test"
import { getAgentToolRestrictions } from "./agent-tool-restrictions"

describe("getAgentToolRestrictions", () => {
  test("omp-strategist has full sub-agent surface allowed", () => {
    const r = getAgentToolRestrictions("omp-strategist")
    expect(r.omp_task_launch).toBe(true)
    expect(r.omp_task_wait_all).toBe(true)
    expect(r.omp_task_wait_any).toBe(true)
    expect(r.omp_task_cancel).toBe(true)
  })

  test("omp-exploiter-mode-1 (leaf agent) cannot spawn sub-agents", () => {
    const r = getAgentToolRestrictions("omp-exploiter-mode-1")
    expect(r.omp_task_launch).toBe(false)
    expect(r.omp_task_wait_all).toBe(false)
    expect(r.omp_task_wait_any).toBe(false)
    expect(r.omp_task_cancel).toBe(false)
  })

  test("omp-exploiter-mode-2 (leaf agent) cannot spawn sub-agents", () => {
    const r = getAgentToolRestrictions("omp-exploiter-mode-2")
    expect(r.omp_task_launch).toBe(false)
    expect(r.omp_task_wait_all).toBe(false)
    expect(r.omp_task_wait_any).toBe(false)
    expect(r.omp_task_cancel).toBe(false)
  })

  test("omp-exploiter-mode-0 (leaf agent) cannot spawn sub-agents", () => {
    const r = getAgentToolRestrictions("omp-exploiter-mode-0")
    expect(r.omp_task_launch).toBe(false)
    expect(r.omp_task_wait_all).toBe(false)
    expect(r.omp_task_wait_any).toBe(false)
    expect(r.omp_task_cancel).toBe(false)
  })

  test("omp-exploiter-mode-9 (leaf agent) cannot spawn sub-agents", () => {
    const r = getAgentToolRestrictions("omp-exploiter-mode-9")
    expect(r.omp_task_launch).toBe(false)
    expect(r.omp_task_wait_all).toBe(false)
    expect(r.omp_task_wait_any).toBe(false)
    expect(r.omp_task_cancel).toBe(false)
  })

  test("bare omp-exploiter (post T8 cutover) returns empty — falls through to default", () => {
    const r = getAgentToolRestrictions("omp-exploiter")
    expect(r).toEqual({})
  })

  test("omp-vulnhunter (leaf agent) cannot spawn sub-agents", () => {
    const r = getAgentToolRestrictions("omp-vulnhunter")
    expect(r.omp_task_launch).toBe(false)
    expect(r.omp_task_cancel).toBe(false)
  })

  test("omp-reverser (leaf agent) cannot spawn sub-agents", () => {
    const r = getAgentToolRestrictions("omp-reverser")
    expect(r.omp_task_launch).toBe(false)
    expect(r.omp_task_cancel).toBe(false)
  })

  test("unknown agent returns empty (full access)", () => {
    const r = getAgentToolRestrictions("some-custom-agent")
    expect(r).toEqual({})
  })
})

describe("DB write ACL Layer 1 (corrected 2026-06-05)", () => {
  const PS = "mcp__omp-db__patch_state"
  const CANDIDATE_CHALLENGE = [
    "mcp__omp-db__create_candidate",
    "mcp__omp-db__patch_candidate",
    "mcp__omp-db__delete_candidate",
    "mcp__omp-db__register_challenge",
    "mcp__omp-db__update_challenge",
  ]

  test("setup / reverser are state writers — patch_state allowed, candidate/challenge denied", () => {
    for (const agent of ["omp-setup", "omp-reverser"]) {
      const r = getAgentToolRestrictions(agent)
      expect(r[PS]).toBeUndefined() // not denied → allowed
      for (const t of CANDIDATE_CHALLENGE) expect(r[t]).toBe(false)
    }
  })

  test("VH / SA / Exploiter are read-only — all DB writes denied", () => {
    for (const agent of [
      "omp-vulnhunter",
      "omp-strategist",
      "omp-exploiter-mode-0",
      "omp-exploiter-mode-9",
    ]) {
      const r = getAgentToolRestrictions(agent)
      expect(r[PS]).toBe(false)
      for (const t of CANDIDATE_CHALLENGE) expect(r[t]).toBe(false)
    }
  })

  test("orchestrator (not in map) keeps full access — no DB writes denied", () => {
    const r = getAgentToolRestrictions("omp-orchestrator")
    expect(r).toEqual({})
  })
})
