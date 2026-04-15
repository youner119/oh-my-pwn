import { describe, expect, test } from "bun:test"
import { createOmpReverserAgent } from "./omp-reverser"

describe("createOmpReverserAgent", () => {
  test("creates agent with all mode (debug)", () => {
    const agent = createOmpReverserAgent("test-model")
    expect(agent.mode).toBe("all")
  })

  test("description frames the agent as program-understanding (not vuln-hunting)", () => {
    const agent = createOmpReverserAgent("test-model")
    expect(agent.description).toBeTruthy()
    expect(typeof agent.description).toBe("string")
    const desc = agent.description as string
    expect(desc.length).toBeGreaterThan(0)
    expect(desc.toLowerCase()).toContain("semantic")
    expect(desc).toContain("neutral")
    expect(desc).toContain("VulnHunter")
  })

  test("prompt mentions the ghidra-mcp read tools", () => {
    const agent = createOmpReverserAgent("test-model")
    expect(agent.prompt).toContain("decompile_function")
    expect(agent.prompt).toContain("list_functions_enhanced")
    expect(agent.prompt).toContain("get_entry_points")
  })

  test("prompt mentions the ghidra-mcp mutation tools (rename + type + comment)", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    // Rename mutations
    expect(p).toContain("rename_function")
    expect(p).toContain("batch_rename_variables")
    // Type mutations
    expect(p).toContain("batch_set_variable_types")
    expect(p).toContain("set_function_prototype")
    // Comments
    expect(p).toContain("batch_set_comments")
  })

  test("prompt specifies type inference rules (array, pointer, primitive, struct)", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Type inference")
    expect(p).toContain("Array inference")
    expect(p).toContain("Pointer inference")
    expect(p).toContain("Primitive refinement")
    expect(p).toContain("Struct inference")
    // Concrete type language
    expect(p).toContain("char[")
    expect(p).toContain("char *")
    expect(p).toContain("size_t")
    expect(p).toContain("struct")
  })

  test("prompt specifies stack-frame extraction and compact distance section", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    // The Reverser must extract rbp-relative offsets and canary info
    expect(p).toContain("Stack frame")
    expect(p).toContain("rbp-relative")
    expect(p).toContain("in_FS_OFFSET")
    expect(p).toContain("stack_canary")
    // Saved rbp and return address are implicit x86_64 SysV facts
    expect(p).toContain("saved_rbp")
    expect(p).toContain("return_address")
    // The Distances subsection is mandatory when stack frame is emitted
    expect(p).toContain("Distances from")
  })

  test("prompt preserves neutrality for type inference and stack distances", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    // Explicit neutrality callout for the new sections
    expect(p).toContain("Neutrality in type inference")
    expect(p).toContain("no verbal interpretation")
  })

  test("prompt specifies the 4-root BFS envelope with default depth 10", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("main")
    expect(p).toContain("_init")
    expect(p).toContain("_fini")
    expect(p).toContain("depth")
    expect(p).toContain("10")
  })

  test("prompt specifies all three markdown artifact paths", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    // Structured analysis (primary VulnHunter context)
    expect(p).toContain("reverser-analysis.md")
    // English narrative research report
    expect(p).toContain("reverser-research.md")
    // Korean narrative research report
    expect(p).toContain("reverser-research.ko.md")
  })

  test("prompt delegates research report structure to templates via tool", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    // The research report workflow references the template tool, not inline structure
    expect(p).toContain("omp_get_template")
    expect(p).toContain("omp_verify_template_output")
    expect(p).toContain("reverser-research-en")
    expect(p).toContain("reverser-research-ko")
    // Verification + retry policy is mentioned
    expect(p).toContain("retries")
    expect(p).toContain("VERIFICATION FAILED")
  })

  test("prompt has Ghidra project setup step 0 before analysis", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    // Step 0 setup sequence
    expect(p).toContain("Ghidra project setup")
    expect(p).toContain("list_instances")
    expect(p).toContain("connect_instance")
    expect(p).toContain("import_file")
    // Dedicated "omp" project
    expect(p).toContain('"omp"')
  })

  test("prompt specifies the program overview + function map structure", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Program Overview")
    expect(p).toContain("Key Observations")
    expect(p).toContain("Function Map")
    expect(p).toContain("Functions (detailed)")
  })

  test("prompt specifies the three-pass self-review (A structural, B semantic, C refinement)", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Pass A")
    expect(p).toContain("Pass B")
    expect(p).toContain("Pass C")
    // Pass descriptions
    expect(p).toContain("Structural")
    expect(p).toContain("Semantic")
    expect(p).toContain("refinement")
  })

  test("prompt forbids exploitability speculation — forbidden words list", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    // Must explicitly label and enumerate forbidden words
    expect(p).toContain("Forbidden")
    expect(p).toContain("vulnerability")
    expect(p).toContain("primitive")
    // Delegating vuln analysis to VulnHunter
    expect(p).toContain("VulnHunter")
    expect(p).toContain("judge exploitability")
  })

  test("prompt includes key-annotations-with-Ghidra-addresses format for Exploiter", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    // Exploiter (T14) reads markdown for breakpoints — addresses must be inline
    expect(p).toContain("Line N (@ 0xADDR)")
    expect(p).toContain("Exploiter")
  })

  test("prompt specifies source-present early-exit with stub artifact", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p.toLowerCase()).toContain("source-present")
    expect(p.toLowerCase()).toContain("stub")
    expect(p.toLowerCase()).toContain("skip")
  })

  test("prompt specifies idempotency / cached-analysis check", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p.toLowerCase()).toContain("cache")
    expect(p).toContain("force")
  })

  test("prompt enforces eager Ghidra mutation (no dry-run gate)", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p.toLowerCase()).toContain("eager")
  })

  test("prompt uses state tools and forbids direct writes to state.json / journal.md", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("omp_read_state")
    expect(p).toContain("omp_patch_state")
    expect(p).toContain("omp_append_journal")
    expect(p).toContain("Never write state.json")
  })
})
