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

  test("Tools table no longer references legacy envsetup / stage / pwno-status tools (T11)", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const p = agent.prompt ?? ""
    // Legacy tools absorbed by omp-setup agent — orchestrator must not
    // call them directly anymore.
    expect(p).not.toContain("`omp_run_envsetup`")
    expect(p).not.toContain("`omp_pwno_status`")
    expect(p).not.toContain("`omp_stage_challenge`")
    expect(p).not.toContain("omp_pwno_container")
    // Loader + read/patch/journal + task surface stay.
    expect(p).toContain("`omp_load_challenge`")
    expect(p).toContain("`omp_task_launch`")
    expect(p).toContain("`omp_task_wait_all`")
    // setup as a category alias for the new agent.
    expect(p).toContain("`setup`/`reverser`/`vulnhunter`/`strategist`/`exploiter`")
  })

  test("Phase 0 is a setup gate that launches omp-setup (T11)", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Setup gate")
    expect(p).toContain("Step 0.1 — Gate decision")
    expect(p).toContain("Step 0.2 — Launch omp-setup")
    expect(p).toContain("Step 0.3 — Check setup result")
    // Gate rules
    expect(p).toContain("setup_unsupported_reason")
    expect(p).toContain("setup_complete")
    expect(p).toContain("binary_input_sha256")
    // Force re-setup keywords (Korean + English) — wrapped across lines
    // in the prompt source, so check the individual fragments.
    expect(p).toContain("재설정")
    expect(p).toContain("setup 초기화")
    expect(p).toContain("re-setup")
    expect(p).toContain("force setup")
    // Launch shape
    expect(p).toContain('agent: "omp-setup"')
  })

  test("Phase 0 success criterion lists the fields downstream agents read", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain('challenge_type === "user-mode-elf"')
    expect(p).toContain("docker_image")
    expect(p).toContain("binary_path")
    expect(p).toContain("binary_input_path")
    expect(p).toContain("extracted_libs")
    expect(p).toContain("workspace_root")
  })

  test("session_id naming scheme: verify-<id>-r<round> / combine-<a>+<b>-r<round>", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("verify-<candidate_id>-r<round>")
    expect(p).toContain("combine-<id_A>+<id_B>-r<round>")
    expect(p).toContain("pipeline_cycle")
    expect(p).toContain("idempotent")
  })

  test("spawn templates label HOST vs CONTAINER paths and derive from workspace rule (T11)", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Challenge dir (HOST)")
    expect(p).toContain("Workspace dir (CONTAINER)")
    expect(p).toContain("Binary (CONTAINER)")
    expect(p).toContain("Libc (CONTAINER)")
    expect(p).toContain("Ld (CONTAINER)")
    // Derived placeholders instead of stale state.pwno_paths.* references
    expect(p).toContain("<binary_in_ctr>")
    expect(p).toContain("<libc_in_ctr>")
    expect(p).toContain("<ld_in_ctr>")
    // Derive rule explicit + extracted_libs forwarding for multi-NEEDED
    expect(p).toContain('"omp-" + basename(state.challenge_dir) + "-" + state.binary_input_sha256.slice(0, 8)')
    expect(p).toContain("state.extracted_libs")
    expect(p).not.toContain("state.pwno_paths")
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

  test("Phase 2 entry attributes pwno-mcp sanity to omp-setup at Phase 0 (T11)", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("user-managed and was sanity-checked by the\nomp-setup agent at Phase 0")
    expect(p).not.toContain("already warm")
    expect(p).not.toContain("sanity-checked at Step 0.3")
  })

  test("Available agents table includes omp-setup (T11)", () => {
    const agent = createOmpOrchestratorAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("`omp-setup`")
    expect(p).toContain("`setup`")
    expect(p).toContain("Phase 0 gate")
  })
})
