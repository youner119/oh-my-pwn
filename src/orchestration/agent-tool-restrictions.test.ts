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

  test("omp-exploiter (leaf agent) cannot spawn sub-agents", () => {
    const r = getAgentToolRestrictions("omp-exploiter")
    expect(r.omp_task_launch).toBe(false)
    expect(r.omp_task_wait_all).toBe(false)
    expect(r.omp_task_wait_any).toBe(false)
    expect(r.omp_task_cancel).toBe(false)
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
