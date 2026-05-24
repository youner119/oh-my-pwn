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

  test("prompt specifies knowledge base consumption protocol", () => {
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    // Step 3 — SKILL.md catalog index read up-front
    expect(p).toContain("knowledge/ctf-pwn/SKILL.md")
    expect(p).toContain("catalog index")
    expect(p).toContain("index familiarisation")
    // Step 8a — detail md lazy reads (including field-notes for atypical)
    expect(p).toContain("knowledge/ctf-pwn/")
    expect(p).toContain("overflow-basics.md")
    expect(p).toContain("heap-techniques.md")
    expect(p).toContain("field-notes.md")
    // Step 8b — domain trigger lazy add (how2heap + kernel)
    expect(p).toContain("knowledge/how2heap/README.md")
    expect(p).toContain("how2heap/glibc_<ver>/<tech>.c")
    // Step 8c — optional indices (notes, writeups)
    expect(p).toContain("knowledge/notes/INDEX.md")
    expect(p).toContain("knowledge/writeups/INDEX.md")
    // Step 8d — writeup matching reads writeup.md only, not exploit.py
    expect(p).toContain("writeup.md")
    expect(p).toContain("DO NOT read")
    expect(p).toContain("exploit.py")
    // Step 8e — cross-category boundary: ctf-reverse off-limits
    expect(p).toContain("Cross-category boundary")
    expect(p).toContain("ctf-reverse")
    // Step 8f — sources/ graceful skip
    expect(p).toContain("sources/")
    expect(p).toContain("skip silently")
    // The "fallback / insufficient" pattern is gone — SKILL.md is now
    // a required up-front read, not a last-resort consult.
    expect(p).not.toContain("if candidates are insufficient")
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
    expect(p).toContain("failed")
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
    expect(p).toContain("Read the ctf-pwn catalog index")
    expect(p).toContain("Analyze ALL functions")
    expect(p).toContain("Cross-reference mitigations")
    expect(p).toContain("Consult the extended knowledge base")
    expect(p).toContain("Rank candidates")
    expect(p).toContain("Return a JSON array")
  })

  test("prompt defines default vs explorer mode dispatch", () => {
    // Explorer mode: VH walks list_methods directly via BN MCP and
    // fills in pseudocode files for functions the Reverser did not
    // pre-save. Default mode: VH trusts Reverser's pre-saved files.
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Mode dispatch")
    expect(p).toContain(`"default"`)
    expect(p).toContain(`"explorer"`)
    expect(p).toMatch(/Default mode|default branch|Default mode — pre-saved/i)
    expect(p).toMatch(/Explorer mode|explorer branch|BN MCP direct query/i)
  })

  test("explorer mode walks list_methods and saves missing pseudocode", () => {
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    // View discovery + list_methods walk.
    expect(p).toContain("list_view")
    expect(p).toContain("list_methods")
    // Skip rules carry over from Reverser's analysis-set policy.
    expect(p).toContain("`sub_`")
    expect(p).toContain("`_dl_`")
    expect(p).toMatch(/__libc_|__GI_/)
    // Disk write of HLIL when pseudocode file does not yet exist.
    expect(p).toContain("decompile_function")
    expect(p).toMatch(/<pseudocode_dir>\/<name>\.txt|pseudocode_dir\/<name>\.txt|pseudocode\/<name>\.txt/)
    expect(p).toMatch(/does NOT exist|not exist on disk|write the returned HLIL/i)
  })

  test("explorer mode obeys BN MCP read-only invariant", () => {
    const agent = createOmpVulnhunterAgent("test-model")
    const p = agent.prompt ?? ""
    // Forbidden mutation tools must be explicitly called out.
    expect(p).toMatch(/MUST NOT call any mutation tool|Read-only BN MCP enforcement|read-only BN MCP/i)
    expect(p).toContain("rename_function")
    expect(p).toContain("set_comment")
    expect(p).toContain("save_bndb")
    expect(p).toMatch(/neutral|user's review artifact/i)
  })
})
