import { describe, expect, test } from "bun:test"
import { getAgentToolRestrictions } from "./agent-tool-restrictions"

describe("getAgentToolRestrictions", () => {
  test("omp-strategist has omp_task: true", () => {
    const r = getAgentToolRestrictions("omp-strategist")
    expect(r.omp_task).toBe(true)
    expect(r.omp_background_output).toBe(true)
  })

  test("omp-exploiter has omp_task: false", () => {
    const r = getAgentToolRestrictions("omp-exploiter")
    expect(r.omp_task).toBe(false)
    expect(r.omp_background_output).toBe(false)
  })

  test("omp-vulnhunter has omp_task: false", () => {
    const r = getAgentToolRestrictions("omp-vulnhunter")
    expect(r.omp_task).toBe(false)
  })

  test("omp-reverser has omp_task: false", () => {
    const r = getAgentToolRestrictions("omp-reverser")
    expect(r.omp_task).toBe(false)
  })

  test("unknown agent returns empty (full access)", () => {
    const r = getAgentToolRestrictions("some-custom-agent")
    expect(r).toEqual({})
  })
})
