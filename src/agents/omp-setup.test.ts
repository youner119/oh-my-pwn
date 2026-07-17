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
    expect(p).toContain("Phase 0 — Detect & Classify")
    expect(p).toContain("Phase 1 — Docker build")
    expect(p).toContain("Phase 2 — Dependency discovery")
    expect(p).toContain("Phase 3 — Extraction + host-side patchelf")
    expect(p).toContain("Phase 4 — Host runtime verify")
    expect(p).toContain("Phase 5 — Stage to workspace")
    expect(p).toContain("Phase 6 — Mark complete")
  })

  test("prompt keys the workspace dir by the DB challenge_id (no omp-<sha8> derivation)", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("<workspace_id> = <challenge_id>")
    expect(p).toContain("state.workspace_root")
    // Concrete example with the DB challenge_id — catches accidental
    // re-templating to a different placeholder.
    expect(p).toContain("afterimage_3f9a2b1c")
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
    expect(p).toContain("mcp__omp-db__patch_state")
    expect(p).toContain("omp_append_journal")
    expect(p).toContain("sole writer")
  })

  test("prompt covers the static-linked branch (patchelf no-op → binary_path = binary_input_path)", () => {
    // User-confirmed semantics: static-linked binaries have no NEEDED and
    // no interpreter, so patchelf is a no-op. The "post-patchelf output"
    // therefore IS the input bytes — `binary_path = binary_input_path` is
    // the no-op result of the patchelf step, not an ad-hoc alias.
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("not a dynamic executable")
    expect(p).toContain('libc_version: "static"')
    expect(p).toContain("extracted_libs: {}")
    // The static branch records binary_path as a copy of binary_input_path
    // (patchelf no-op), so downstream agents see a populated invariant.
    expect(p).toContain("binary_path: <state.binary_input_path>")
  })

  test("prompt generalises D8 (diagnose-only, retry 0) to ALL phases", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("D8 generalised")
    expect(p).toContain("Retry 0")
    expect(p).toContain("setup_unsupported_reason")
  })

  test("prompt requires submit + self-terminate at every exit (parent completion signal)", () => {
    // omp-setup is a leaf sub-agent launched via omp_task_launch. The parent
    // detects completion ONLY when the agent calls omp_task_terminate; a
    // missing submission makes the parent mis-mark it crashed. Every leaf
    // agent (VH/SA/reverser) carries this protocol — setup must too, or it
    // never self-terminates. Guards against regressing that omission.
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Termination protocol")
    expect(p).toContain("omp_task_submit")
    expect(p).toContain("omp_task_terminate")
    expect(p).toContain("self")
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

  test("prompt guards Object_Object regression — binary_path must be patched copy, NOT binary_input_path", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    // Self-check + concrete counter-example
    expect(p).toContain("binary_path` MUST point at the patched copy")
    expect(p).toContain("NOT at `binary_input_path")
    expect(p).toContain("re-read your own `mcp__omp-db__patch_state` payload")
    // Success criterion makes the inequality explicit
    expect(p).toContain("state.binary_path !== state.binary_input_path")
  })

  test("prompt guards extracted_libs must include the ld interpreter entry", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    // explicit ld inclusion rule + concrete example with ld-linux key
    expect(p).toContain("MUST include EVERY file you extracted in")
    expect(p).toContain('"ld-linux-x86-64.so.2":')
    expect(p).toContain("Omitting ld from the map")
    // Success criterion mentions the ld entry too
    expect(p).toContain('includes the ld entry')
  })

  test("Phase 0 owns input-contract detection (contract-load-detect-split D2)", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    // Phase 0 seeds binary_input_path / sha / dockerfile_path / source_*
    // (loader no longer touches them per D1/D2).
    expect(p).toContain("contract-load-detect-split.md")
    expect(p).toContain("loader no longer touches")
    expect(p).toContain("binary_input_path")
    expect(p).toContain("binary_input_sha256")
    expect(p).toContain("dockerfile_path")
    expect(p).toContain("source_present")
  })

  test("Phase 0 emits setup_blocker on ambiguous-binary and stops (contract-load-detect-split D5)", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Ambiguous binary handoff")
    expect(p).toContain('kind: "ambiguous-binary"')
    expect(p).toContain("candidates:")
    expect(p).toContain("setup_complete MUST stay false")
    // Re-entry: when orchestrator clears the blocker by writing
    // binary_input_path, Phase 0 must skip the scan.
    expect(p).toContain("Re-entry shortcut")
    expect(p).toContain("skip the ELF-candidate scan")
  })

  test("etc free-form metadata guide is present (contract-load-detect-split D7)", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    // Naming + write-policy boilerplate
    expect(p).toContain("Free-form metadata via `etc`")
    expect(p).toContain("only allowed writers")
    expect(p).toContain("snake_case")
    // Kernel example anchors readers to the most common no-binary case
    expect(p).toContain("kernel_vmlinux_path")
    expect(p).toContain("kernel_qemu_cmd")
    expect(p).toContain("kernel_kaslr")
  })

  test("Phase 0 — no-binary unsupported buckets leave binary_input_path undefined (D3)", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    // The D3 relaxation: kernel-pwn / source-only / library-only buckets
    // may seed no binary_input_path at all. The prompt must teach this.
    expect(p).toContain("Omit when")
    expect(p).toContain("source-only")
    expect(p).toContain("kernel")
  })

  test("Phase 5 stages from input/image, not from patched artifacts (2026-05-21)", () => {
    const agent = createOmpSetupAgent("test-model")
    const p = agent.prompt ?? ""
    // Invariant must be spelled out — the bug was Phase 5 copying
    // artifacts (already absolute-path NEEDED) → workspace and re-running
    // patchelf, which silently no-ops the --replace-needed pass.
    expect(p).toContain("never re-patch a patched ELF")
    expect(p).toContain("no-ops")
    // Binary source must be the unpatched input, not the artifacts copy.
    expect(p).toContain("Binary — fresh from host input")
    expect(p).toContain("<state.binary_input_path>")
    // Libraries / ld must come from the docker image, using the Phase 2
    // ldd map (not the artifacts path).
    expect(p).toContain("Each library — fresh from image")
    expect(p).toContain('source: "image"')
    expect(p).toContain("image abs path from Phase 2")
    // Verification step prevents silent regression — the agent is told
    // to readelf -d after patchelf and re-stage if NEEDED still points at
    // <artifacts_dir>.
    expect(p).toContain("readelf -d")
    expect(p).toContain("re-stage from input/image")
  })
})
