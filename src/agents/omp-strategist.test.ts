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
    expect(desc.toLowerCase()).toContain("primitive")
    expect(desc).toContain("Exploiter")
    expect(desc.toLowerCase()).not.toContain("pwntools")
  })

  test("prompt declares scope: verify/combine, not write code", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("DO NOT")
    expect(p).toContain("Exploiter writes all code")
    expect(p).toContain("sole writer")
  })

  test("prompt has two task types: VERIFY and COMBINE", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Type 1: VERIFY")
    expect(p).toContain("Type 2: COMBINE")
    expect(p).toContain("gives")
    expect(p).toContain("needs")
  })

  test("prompt reads state as shared blackboard", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("omp_read_state")
    expect(p).toContain("shared blackboard")
    expect(p).toContain("vuln_candidates")
    expect(p).toContain("poc_script_path")
  })

  test("prompt reads reverser analysis", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("reverser_summary_path")
    expect(p).toContain("stack frames")
    expect(p).toContain("function addresses")
  })

  test("prompt references TechniqueKB", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("knowledge/techniques/index.md")
    expect(p).toContain("chain")
  })

  test("prompt spawns Exploiter via omp_task (sync)", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("omp_task")
    expect(p).toContain("omp-exploiter")
    expect(p).toContain("run_in_background: false")
  })

  test("prompt returns structured JSON with gives/needs/poc_script_path", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain('"gives"')
    expect(p).toContain('"needs"')
    expect(p).toContain('"poc_script_path"')
    expect(p).toContain('"combined_from"')
    expect(p).toContain('"flag"')
    expect(p).toContain('"status"')
  })

  test("prompt specifies retry with max 3", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("3 retries")
    expect(p).toContain("inconclusive")
  })

  test("prompt specifies mitigation awareness", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Mitigation-aware")
    expect(p).toContain("Canary")
    expect(p).toContain("PIE")
    expect(p).toContain("NX")
  })

  test("prompt enforces one primitive per invocation", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("One primitive per invocation")
    expect(p).toContain("Orchestrator manages")
  })

  test("prompt does not write state", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("DO NOT: call `omp_patch_state`")
  })
})
