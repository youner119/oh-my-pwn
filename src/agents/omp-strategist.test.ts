import { describe, expect, test } from "bun:test"
import { createOmpStrategistAgent } from "./omp-strategist"

describe("createOmpStrategistAgent", () => {
  test("creates agent with all mode (debug)", () => {
    const agent = createOmpStrategistAgent("test-model")
    expect(agent.mode).toBe("all")
  })

  test("description frames as plan designer, not code writer", () => {
    const agent = createOmpStrategistAgent("test-model")
    const desc = agent.description as string
    expect(desc.toLowerCase()).toContain("plan")
    expect(desc).toContain("Exploiter")
    expect(desc.toLowerCase()).not.toContain("pwntools")
  })

  test("prompt declares scope: design strategy, not write code", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("DO NOT")
    expect(p).toContain("pwntools")
    expect(p).toContain("Exploiter writes all code")
  })

  test("prompt uses state tools", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("omp_read_state")
    expect(p).toContain("omp_patch_state")
    expect(p).toContain("omp_append_journal")
  })

  test("prompt reads reverser analysis for structural context", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("reverser_summary_path")
    expect(p).toContain("Stack frame")
    expect(p).toContain("Function Map")
    expect(p).toContain("Ghidra instruction addresses")
  })

  test("prompt reads vuln_candidates from state", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("vuln_candidates")
    expect(p).toContain("candidate")
    expect(p).toContain("primitive")
    expect(p).toContain("confidence")
  })

  test("prompt supports two modes: verification and exploit chain", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Mode A")
    expect(p).toContain("Mode B")
    expect(p).toContain("verification")
    expect(p).toContain("Exploit chain")
  })

  test("prompt supports multi-candidate combination", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Candidate combination")
    expect(p).toContain("Verify before combine")
    expect(p).toContain("Dependency ordering")
    expect(p).toContain("Multi-candidate steps")
  })

  test("prompt specifies step structure with goal and expected_result", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("goal")
    expect(p).toContain("expected_result")
    expect(p).toContain("candidate_id")
    expect(p).toContain("stages")
  })

  test("prompt references TechniqueKB for chain field", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("knowledge/techniques/index.md")
    expect(p).toContain("chain")
  })

  test("prompt specifies retry logic with budget of 3", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Retry")
    expect(p).toContain("3")
    expect(p).toContain("exhausted")
    expect(p).toContain("escalate")
    expect(p).toContain("VulnHunter")
  })

  test("prompt specifies failure diagnosis before retry", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("failure_reason")
    expect(p).toContain("Diagnose")
    expect(p).toContain("offset wrong")
  })

  test("prompt cross-references mitigations for chaining", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Mitigation-driven chaining")
    expect(p).toContain("Canary on")
    expect(p).toContain("PIE on")
    expect(p).toContain("NX on")
    expect(p).toContain("Full RELRO")
  })

  test("prompt specifies strategist-plan.md artifact", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("strategist-plan.md")
    expect(p).toContain("strategist_plan_path")
    expect(p).toContain("strategist_planned_at")
  })

  test("prompt specifies incremental proof principle", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Incremental proof")
    expect(p).toContain("one thing")
  })

  test("prompt mentions process() and remote() execution modes", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("process()")
    expect(p).toContain("remote()")
    expect(p).toContain("Docker")
  })
})
