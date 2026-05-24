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

  test("prompt forbids writing `etc` (contract-load-detect-split D7)", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    // Reverser may read state.etc but must never include it in patches.
    expect(p).toContain("NEVER include `etc` in your patch")
    expect(p).toContain("write-restricted to omp-setup / omp-orchestrator")
    expect(p).toContain("freely READ `state.etc`")
  })

  test("prompt mentions the BN MCP read tools", () => {
    const agent = createOmpReverserAgent("test-model")
    expect(agent.prompt).toContain("decompile_function")
    expect(agent.prompt).toContain("list_methods")
    expect(agent.prompt).toContain("get_entry_points")
  })

  test("prompt mentions the BN MCP mutation tools (rename + type + comment)", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    // Rename mutations
    expect(p).toContain("rename_function")
    expect(p).toContain("rename_multi_variables")
    // Type mutations
    expect(p).toContain("retype_variable")
    expect(p).toContain("set_function_prototype")
    // Comments
    expect(p).toContain("set_comment")
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

  test("prompt specifies stack-frame via get_stack_frame_vars and distance section", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    // BN API for stack frame
    expect(p).toContain("get_stack_frame_vars")
    expect(p).toContain("Stack frame")
    // saved_rbp and return_address in output
    expect(p).toContain("saved_rbp")
    expect(p).toContain("return_addr")
    // Distance section
    expect(p).toContain("Distances from")
  })

  test("prompt preserves neutrality for type inference", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Neutrality in type inference")
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
    expect(p).toContain("reverser-analysis.md")
    expect(p).toContain("reverser-research.md")
    expect(p).toContain("reverser-research.ko.md")
  })

  test("prompt delegates research report structure to templates via tool", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("omp_get_template")
    expect(p).toContain("omp_verify_template_output")
    expect(p).toContain("reverser-research-en")
    expect(p).toContain("reverser-research-ko")
    expect(p).toContain("retries")
  })

  test("prompt has BN setup step 0 before analysis", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("BN setup")
    expect(p).toContain("get_binary_status")
    expect(p).toContain("load")
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
    expect(p).toContain("Structural")
    expect(p).toContain("Semantic")
    expect(p).toContain("refinement")
  })

  test("prompt forbids exploitability speculation — forbidden words list", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Forbidden")
    expect(p).toContain("vulnerability")
    expect(p).toContain("primitive")
    expect(p).toContain("VulnHunter")
    expect(p).toContain("judge exploitability")
  })

  test("prompt includes key-annotations-with-addresses format for Exploiter", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("addresses")
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

  test("prompt enforces eager BN mutation (no dry-run gate)", () => {
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

  test("prompt specifies batch_decompile_to_file and save_bndb", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("batch_decompile_to_file")
    expect(p).toContain("save_bndb")
    expect(p).toContain(".bndb")
  })

  // K4 — Knowledge integration: Reverser prompt surgery
  // Spec: .omc/specs/deep-interview-knowledge-integration.md

  test("K4: Knowledge base consumption section exists with layer separation", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Knowledge base consumption")
    // BN HLIL = raw, catalog = pattern recognition guide (D-K4-2)
    expect(p).toMatch(/BN HLIL.*=.*raw|raw.*ground truth/i)
    expect(p).toMatch(/catalog.*pattern recognition guide|pattern recognition/i)
    expect(p).toMatch(/different layers|NOT competing/i)
    expect(p).toMatch(/never overrides BN HLIL|HLIL output itself is what you trust/i)
  })

  test("K4: Tier 1 — SKILL.md index read once before Pass 1 (D-K4-1)", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    // Tier 1 strict — catalog index familiarisation
    expect(p).toMatch(/Tier 1/)
    expect(p).toContain("ctf-reverse/SKILL.md")
    expect(p).toMatch(/index familiarisation|familiarisation/i)
    expect(p).toMatch(/once|read once/i)
    // Required sequence step 4 prologue references it
    expect(p).toMatch(/Prologue.*Tier 1|before Pass 1 starts/i)
  })

  test("K4: Tier 2 — detail md lazy reads with 5-category trigger map", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toMatch(/Tier 2/)
    // All 5 main categories present in trigger map
    expect(p).toContain("anti-analysis.md")
    expect(p).toContain("languages.md")
    expect(p).toContain("patterns-ctf.md")
    expect(p).toContain("patterns-runtime.md")
    expect(p).toContain("platforms.md")
    expect(p).toContain("tools-emulation.md")
    // Lazy read discipline
    expect(p).toMatch(/at most.*1-2|1-2 files per function/i)
    expect(p).toMatch(/do NOT bulk read|not bulk/i)
    // field-notes for long-tail
    expect(p).toContain("field-notes.md")
    // "hint, not exhaustive" caveat
    expect(p).toMatch(/HINT, not exhaustive|not exhaustive/i)
  })

  test("K4: Cross-category boundary — ctf-pwn + how2heap OFF-LIMITS (D-K4-4)", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    // Both forbidden vendors mentioned explicitly
    expect(p).toMatch(/DO NOT read `ctf-pwn\/`, `how2heap\/`|ctf-pwn\/.*how2heap\/.*OFF-LIMITS/is)
    // Even-when guard: overflow/heap pattern doesn't unlock
    expect(p).toMatch(/Even if the binary clearly exhibits.*overflow.*heap|even when.*exhibits/is)
    expect(p).toMatch(/NOT consult.*ctf-pwn|NOT consult.*how2heap/is)
    // Role separation rationale
    expect(p).toMatch(/Role separation|VH \/ SA \/ Exploiter territory/i)
  })

  test("K4: sources/ graceful skip + Tier 3 optional indices", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    // sources/ graceful
    expect(p).toContain("sources/")
    expect(p).toMatch(/skip silently|graceful skip/i)
    expect(p).toMatch(/git-ignored|machine-local/i)
    // Tier 3 optional indices
    expect(p).toMatch(/Tier 3/)
    expect(p).toContain("notes/INDEX.md")
    expect(p).toContain("writeups/INDEX.md")
    expect(p).toMatch(/may be empty|may be absent/)
  })

  test("K4: Neutrality reminder — reading catalog ≠ copying its vocabulary", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    // Reverser-specific guard — forbidden words still apply when reading catalog
    expect(p).toMatch(/Neutrality reminder/i)
    expect(p).toMatch(/Reading the catalog does NOT mean.*copy.*vocabulary|catalog reading.*understanding/i)
    expect(p).toMatch(/Forbidden words section still applies|forbidden words still apply/i)
    // Concrete ❌/✅ example for neutrality (anti-debug pattern)
    expect(p).toMatch(/Anti-debug check that prevents debugging|TracerPid/i)
  })

  test("K4: Key principles include Knowledge boundary + Catalog vs HLIL layer", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toMatch(/Knowledge boundary \(K4\)/)
    expect(p).toMatch(/Catalog vs HLIL = different layers|different layers/i)
    expect(p).toMatch(/ctf-pwn\/.*off-limits|off-limits/i)
  })

  test("reverser-analysis.md template carries Address convention block (2026-05-21)", () => {
    const agent = createOmpReverserAgent("test-model")
    const p = agent.prompt ?? ""
    // The output-file template must include an Address convention section
    // so SA / Exploiter can interpret every BN VA in the document.
    expect(p).toContain("## Address convention")
    expect(p).toContain("PIE (relocatable)")
    expect(p).toContain("BN imagebase")
    // The formulas must spell out BN_VA / RVA / runtime so the consumer
    // doesn't reinvent them (the vuln_1 / afterimage failure mode came
    // from each downstream agent guessing its own convention).
    expect(p).toContain("BN_VA - imagebase")
    expect(p).toContain("pie_base + RVA")
    expect(p).toContain("vmmap")
    // Required sequence must instruct Reverser to capture image_base /
    // relocatable from get_binary_status (with fallback) so the
    // convention block has real values, not placeholders.
    expect(p).toContain("get_binary_status")
    expect(p).toContain("image_base")
    expect(p).toContain("relocatable")
    expect(p).toContain("0x400000")
  })
})
