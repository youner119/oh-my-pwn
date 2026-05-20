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

  test("prompt references the ctf-pwn vendor catalog", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("knowledge/ctf-pwn/SKILL.md")
    expect(p).toContain("chain")
  })

  test("prompt spawns Exploiter via launch + wait_all (Pattern 1)", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("omp_task_launch")
    expect(p).toContain("omp_task_wait_all")
    expect(p).toContain("exploiter")
    expect(p).not.toContain("run_in_background")
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

  test("prompt has explicit path forwarding section (host vs container)", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Path forwarding")
    expect(p).toContain("host path")
    expect(p).toContain("container paths")
    expect(p).toContain("/workspace/<challenge_id>")
  })

  test("prompt forbids path rewriting and session_id invention", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("DO NOT: rewrite paths")
    expect(p).toContain("DO NOT: invent a `session_id`")
    expect(p).toContain("sole id-allocator")
  })

  test("spawn template labels paths HOST vs CONTAINER", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("(HOST — for Write/Read")
    expect(p).toContain("(CONTAINER — for pwno-mcp")
    expect(p).toContain("assigned by Orchestrator")
  })

  test("spawn template forwards reverser artifacts paths", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Reverser artifacts (HOST)")
    expect(p).toContain(".omp/artifacts/")
    expect(p).toContain("reverser-analysis.md")
    expect(p).toContain("pseudocode/")
    expect(p).toMatch(/Read these FIRST|do not call binja_\*/)
  })

  test("prompt emits recommended_mode hint with 2-way classification", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    // Step 4b classification rule exists
    expect(p).toContain("Step 4b")
    expect(p).toContain("recommended_mode")
    // Both modes documented
    expect(p).toMatch(/recommended_mode:\s*1/)
    expect(p).toMatch(/recommended_mode:\s*2/)
    // No Mode 4 — pwncli covers no-input inspection too
    expect(p).not.toMatch(/recommended_mode:\s*4/)
    // Write-side primitives → Mode 2
    expect(p).toMatch(/\*_write|tcache_poison|house_of_/)
    // Read/leak → Mode 1
    expect(p).toMatch(/fmt_string_read|_leak/)
    // Spawn template forwards the hint
    expect(p).toMatch(/recommended_mode:\s*<1\|2>/)
  })

  test("prompt delegates execution mode choice to Exploiter", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Execution mode")
    expect(p).toContain("Exploiter's call")
    // SA must not pre-prescribe modes
    expect(p).toContain("don't pre-prescribe it")
  })

  test("prompt attributes workspace staging to omp-setup Phase 5 (T15.5)", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("omp-setup agent")
    expect(p).toContain("Phase 5")
    // Legacy tool name stays only in the doc-comment header; prompt body
    // (the STRATEGIST_PROMPT template) must not instruct calling it.
    const promptBody = p.split("const STRATEGIST_PROMPT").slice(-1)[0] ?? p
    expect(promptBody).not.toContain("`omp_stage_challenge`")
  })

  test("prompt teaches extracted_libs map for multi-NEEDED leak primitives (T15.5)", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("extracted_libs")
    // workspace_id derive rule embedded in path forwarding rules
    expect(p).toContain('omp-<basename(challenge_dir)>-<sha8>')
    expect(p).toContain('state.binary_input_sha256.slice(0, 8)')
  })

  test("Key principles include Path forwarding rule", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Path forwarding only")
  })
})
