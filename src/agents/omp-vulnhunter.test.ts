import { describe, expect, test } from "bun:test"
import { createOmpVulnhunterAgent } from "./omp-vulnhunter"

describe("createOmpVulnhunterAgent", () => {
  test("creates agent with all mode (debug)", () => {
    const agent = createOmpVulnhunterAgent("test-model")
    expect(agent.mode).toBe("all")
  })

  test("description frames as vulnerability finder, not exploit designer", () => {
    const agent = createOmpVulnhunterAgent("test-model")
    const desc = agent.description as string
    expect(desc.toLowerCase()).toContain("vulnerability")
    expect(desc.toLowerCase()).toContain("candidate")
    expect(desc).toContain("StrategyAgent")
  })

  test("prompt declares scope: find vulns, not design exploits", () => {
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    // DO: identify vulnerabilities
    expect(p).toContain("identify")
    expect(p).toContain("buffer overflow")
    expect(p).toContain("format string")
    expect(p).toContain("use-after-free")
    // DO NOT: exploit steps
    expect(p).toContain("DO NOT")
    expect(p).toContain("StrategyAgent")
    expect(p).toContain("padding")
    expect(p).toContain("ROP")
  })

  test("prompt reads via omp_read_state but does NOT write state or journal (ensemble paradigm)", () => {
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    // Read-only state access.
    expect(p).toContain("omp_read_state")
    // Explicit prohibition on writes — Orchestrator is sole writer.
    expect(p).toContain("Do NOT call")
    expect(p).toContain("omp_patch_state")
    expect(p).toContain("omp_append_journal")
    expect(p).toContain("sole writer")
  })

  test("prompt reads reverser_summary_path for binary analysis", () => {
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("reverser_summary_path")
    expect(p).toContain("reverser-analysis.md")
  })

  test("prompt handles source-present mode", () => {
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("source_present")
    expect(p).toContain("source_paths")
    expect(p).toContain("C source")
  })

  test("prompt enforces hint-not-filter contract with Reverser output", () => {
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    // Must analyze ALL functions regardless of Reverser naming
    expect(p.toLowerCase()).toContain("hint")
    expect(p.toLowerCase()).toContain("filter")
    expect(p).toContain("ALL functions")
    expect(p).toContain("safe_input_handler")
  })

  test("prompt cross-references mitigations", () => {
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("mitigations")
    expect(p).toContain("canary")
    expect(p).toContain("pie")
    expect(p).toContain("relro")
    expect(p).toContain("nx")
    expect(p).toContain("libc_version")
  })

  test("prompt specifies TechniqueKB consultation as fallback", () => {
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    // TechniqueKB paths
    expect(p).toContain("knowledge/techniques/index.md")
    expect(p).toContain("knowledge/techniques/stack_bof.md")
    // Fallback nature
    expect(p).toContain("fallback")
    expect(p).toContain("insufficient")
  })

  test("prompt specifies candidate fields matching ChallengeState schema", () => {
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("vuln_candidates")
    // Required candidate fields appear as JSON keys (the prompt's
    // output format example).
    expect(p).toContain('"id"')
    expect(p).toContain('"primitive"')
    expect(p).toContain('"location"')
    expect(p).toContain('"confidence"')
    expect(p).toContain('"rationale"')
  })

  test("prompt returns a JSON array on stdout (no markdown artifact)", () => {
    // Ensemble paradigm: VH produces no on-disk artifact. The single
    // output channel is a JSON array on stdout that the Orchestrator
    // merges across ensemble instances.
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("JSON array")
    expect(p).toContain("stdout")
    // Markdown artifact + per-VH state field references are gone.
    expect(p).not.toContain("vulnhunter-analysis.md")
    expect(p).not.toContain("vulnhunter_analysis_path")
    expect(p).not.toContain("vulnhunter_analyzed_at")
  })

  test("prompt handles verification result updates", () => {
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("verified")
    expect(p).toContain("verification_result")
    expect(p).toContain("confirmed")
    expect(p).toContain("disproved")
  })

  test("prompt signals stagnation via empty JSON array", () => {
    // VH no longer appends a journal "no more candidates" entry — the
    // Orchestrator records stagnation when ensemble outputs collapse to
    // empty arrays.
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("[]")
    expect(p).toContain("stagnation")
  })

  test("prompt specifies confidence scoring criteria", () => {
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("confidence")
    expect(p).toContain("0.0")
    expect(p).toContain("1.0")
    expect(p).toContain("evidence")
  })

  test("prompt specifies required sequence with numbered steps", () => {
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Required sequence")
    // Key steps — ensemble paradigm: read + analyze + return JSON.
    expect(p).toContain("omp_read_state")
    expect(p).toContain("Analyze ALL functions")
    expect(p).toContain("Cross-reference mitigations")
    expect(p).toContain("TechniqueKB")
    expect(p).toContain("Rank candidates")
    expect(p).toContain("Return a JSON array")
  })
})
