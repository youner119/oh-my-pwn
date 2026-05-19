import { describe, expect, test } from "bun:test"
import { createOmpSetupAgent } from "./omp-setup"

describe("createOmpSetupAgent", () => {
  test("creates agent with all mode (debug)", () => {
    const agent = createOmpSetupAgent("test-model")
    expect(agent.mode).toBe("all")
  })

  test("description frames the agent as single-transaction setup", () => {
    const agent = createOmpSetupAgent("test-model")
    expect(agent.description).toBeTruthy()
    const desc = agent.description as string
    expect(desc.length).toBeGreaterThan(0)
    expect(desc.toLowerCase()).toContain("setup")
    expect(desc).toContain("setup_complete")
    expect(desc).toContain("Scope discipline")
  })

  test("prompt enforces Scope discipline (D10) with concrete forbidden lists", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Scope discipline")
    expect(p).toContain("D10")
    expect(p).toContain("VulnHunter")
    expect(p).toContain("StrategyAgent")
    expect(p).toContain("Exploiter")
    // Forbidden primitive vocabulary
    expect(p).toContain("stack_bof")
    expect(p).toContain("fmt_string")
    expect(p).toContain("heap_uaf")
    // Self-check + drop-the-sentence rule
    expect(p).toContain("Self-check rule")
    expect(p).toContain("drop the sentence")
  })

  test("prompt names all six phases (0..6) with required transitions", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Phase 0 — Inspect & Classify")
    expect(p).toContain("Phase 1 — Docker build")
    expect(p).toContain("Phase 2 — Dependency discovery")
    expect(p).toContain("Phase 3 — Extraction + host-side patchelf")
    expect(p).toContain("Phase 4 — Host runtime verify")
    expect(p).toContain("Phase 5 — Stage to workspace")
    expect(p).toContain("Phase 6 — Mark complete")
  })

  test("prompt embeds the workspace-id derivation rule (omp-<basename>-<sha8>)", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain('"omp-" + basename(state.challenge_dir) + "-" + state.binary_input_sha256.slice(0, 8)')
    expect(p).toContain("state.workspace_root")
    // Concrete example with afterimage/a1b2c3d4 — catches accidental
    // re-templating to a different placeholder.
    expect(p).toContain("omp-afterimage-a1b2c3d4")
  })

  test("prompt requires explicit --replace-needed (not --set-rpath) per D3", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("--replace-needed")
    expect(p).toContain("DT_RUNPATH is NOT transitive")
  })

  test("prompt mentions all four omp_setup_* atomic tools by name", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("omp_setup_docker_build")
    expect(p).toContain("omp_setup_extract_file")
    expect(p).toContain("omp_setup_patch_elf")
    expect(p).toContain("omp_setup_verify_runtime")
  })

  test("prompt grants sole-writer status during setup (D1 relaxation)", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    // Setup IS the writer for state + journal during its transaction.
    expect(p).toContain("omp_patch_state")
    expect(p).toContain("omp_append_journal")
    expect(p).toContain("sole writer")
  })

  test("prompt covers the static-linked branch explicitly", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("not a dynamic executable")
    expect(p).toContain('libc_version: "static"')
    expect(p).toContain("extracted_libs: {}")
  })

  test("prompt generalises D8 (diagnose-only, retry 0) to ALL phases", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("D8 generalised")
    expect(p).toContain("Retry 0")
    expect(p).toContain("setup_unsupported_reason")
  })

  test("prompt forbids mutating binary_input_path + sudo + .omp deletion", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Forbidden patterns")
    expect(p).toContain("`sudo` for anything")
    expect(p).toContain("rm -rf")
    expect(p).toContain("Mutating `state.binary_input_path`")
  })

  test("prompt defines the success criterion fields the orchestrator reads", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Single-transaction success criterion")
    expect(p).toContain("state.setup_complete         === true")
    expect(p).toContain('state.challenge_type         === "user-mode-elf"')
  })

  test("prompt routes via image-ldd, not hardcoded LIBC_CANDIDATES", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("docker run --rm <image> ldd <binary_container_path>")
    expect(p).toContain("SONAME → image-path map")
  })
})
