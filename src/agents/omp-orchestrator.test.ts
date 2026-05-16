import { describe, expect, test } from "bun:test"
import { createOmpOrchestratorAgent } from "./omp-orchestrator"

describe("createOmpOrchestratorAgent", () => {
  test("creates agent with all mode", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    expect(agent.mode).toBe("all")
  })

  test("description identifies orchestrator + parallel pipeline", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const desc = agent.description as string
    expect(desc.toLowerCase()).toContain("orchestrator")
    expect(desc.toLowerCase()).toContain("parallel")
  })

  test("declares sole state writer + sole id-allocator", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("SOLE STATE WRITER")
    expect(p).toContain("sole id-allocator")
  })

  test("Tools table references the D-1 surface (status + stage), not the legacy container tool", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("`omp_pwno_status`")
    expect(p).toContain("`omp_stage_challenge`")
    // legacy tool gone everywhere in prompt
    expect(p).not.toContain("omp_pwno_container")
  })

  test("Phase 0 includes pwno-mcp sanity check and surfaces hint on failure", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Step 0.3")
    expect(p).toContain("omp_pwno_status()")
    expect(p).toContain("healthy: true")
    expect(p).toContain("healthy: false")
    expect(p).toContain("surface the `hint` field")
    expect(p).toContain("user's responsibility")
  })

  test("Phase 0 stages challenge files and records container paths to state.pwno_paths", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Step 0.4")
    expect(p).toContain("omp_stage_challenge")
    expect(p).toContain("pwno_paths")
    expect(p).toContain("workspace_dir")
    expect(p).toContain("container_path")
  })

  test("session_id naming scheme: verify-<id>-r<round> / combine-<a>+<b>-r<round>", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("verify-<candidate_id>-r<round>")
    expect(p).toContain("combine-<id_A>+<id_B>-r<round>")
    expect(p).toContain("pipeline_cycle")
    expect(p).toContain("idempotent")
  })

  test("spawn templates label HOST vs CONTAINER paths and forward state.pwno_paths", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Challenge dir (HOST)")
    expect(p).toContain("Binary (CONTAINER)")
    expect(p).toContain("Libc (CONTAINER)")
    expect(p).toContain("Ld (CONTAINER)")
    expect(p).toContain("state.pwno_paths.binary")
  })

  test("Phase 4 termination does NOT call any container stop tool", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Container cleanup is the **user's job**")
    expect(p).not.toMatch(/action:\s*"stop"/)
  })

  test("Reverser entry in agents table references Binary Ninja, not Ghidra", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Binary Ninja MCP")
    expect(p).toContain("binja_*")
    expect(p).not.toContain("Ghidra-MCP")
  })

  test("Phase 2 entry no longer claims container was warmed by us", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("user-managed and was sanity-checked at Step 0.3")
    expect(p).not.toContain("already warm")
  })
})
