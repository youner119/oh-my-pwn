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
    expect(p).toContain("mcp__omp-db__read_state")
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

  test("prompt specifies knowledge base consumption protocol", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    // Step 2 — SKILL.md catalog index up-front
    expect(p).toContain("knowledge/ctf-pwn/SKILL.md")
    expect(p).toContain("catalog index")
    expect(p).toContain("index familiarisation")
    // Step 4a — detail md lazy (ctf-pwn + field-notes for atypical chains)
    expect(p).toContain("knowledge/ctf-pwn/")
    expect(p).toContain("heap-techniques.md")
    expect(p).toContain("field-notes.md")
    // Step 4b — domain trigger lazy (how2heap, kernel)
    expect(p).toContain("knowledge/how2heap/README.md")
    // Step 4c — optional indices
    expect(p).toContain("knowledge/notes/INDEX.md")
    expect(p).toContain("knowledge/writeups/INDEX.md")
    // Step 4d — writeup matching: SA-specific key + chain structure boundary
    expect(p).toContain("vuln_pattern + chain + mitigations")
    expect(p).toContain("writeup.md")
    expect(p).toContain("chain structure")
    expect(p).toContain("Default: do NOT read")
    expect(p).toContain("exploit.py")
    expect(p).toContain("payload internals")
    // SA's chain focus (Step 4a/4d both touch this)
    expect(p).toContain("chain")
    // Step 4e — cross-category boundary
    expect(p).toContain("Cross-category boundary")
    expect(p).toContain("ctf-reverse")
    // Step 4f — sources/ graceful skip
    expect(p).toContain("sources/")
    expect(p).toContain("skip silently")
  })

  test("prompt drives Exploiter as resumable worker (launch + resume + terminate)", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("omp_task_launch")
    expect(p).toContain("omp_task_wait_all")
    expect(p).toContain("omp_task_resume")
    expect(p).toContain("omp_task_terminate")
    expect(p).toContain("exploiter")
    expect(p).not.toContain("run_in_background")
  })

  test("prompt guards against re-waiting after a result (resumable-worker deadlock)", () => {
    // wait_all consumes the Exploiter's submission; the Exploiter then stays
    // running/idle (resumable) awaiting resume/terminate. A parent that re-waits
    // "to reach terminal status" deadlocks: the submit is already consumed and
    // the worker never self-terminates. The loop must act on the first result
    // (terminate/resume/return) and only re-wait after a new resume command.
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("never re-wait")
    expect(p).toContain("consumes it")
    expect(p).toContain("deadlock")
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

  test("prompt caps Exploiter commands at max_retries_per_candidate (default 3)", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("max_retries_per_candidate")
    expect(p).toContain("up to 2 resumes")
    expect(p).toContain("inconclusive")
  })

  test("prompt allows literal primitive specialisation but forbids synthesis (2026-05-21)", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    // SA may narrow a broad VH primitive (`uaf` → `uaf_read`) and the
    // prompt must say so explicitly.
    expect(p).toContain("Primitive specialisation")
    expect(p).toContain("narrows")
    expect(p).toContain("more specific capability")
    // The narrowing must be literal, not synthesis — the same rule the
    // Orchestrator's dedup step enforces. Both ends must agree so the
    // information-gain edit can't be smuggled into a synthesis path.
    expect(p).toContain("Narrowing must be literal, not synthesised")
    expect(p).toContain("`uaf_read_write`")
    // If SA's evidence is unrelated to the candidate, route it via
    // verification_blockers — never silently rewrite the candidate.
    expect(p).toContain("evidence is unrelated")
    expect(p).toContain("verification_blockers")
  })

  test("prompt routes methodology failures via verification_blockers, not new_candidates (2026-05-21)", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    // The result-JSON shape must advertise verification_blockers and must
    // not carry the retired new_candidates slot.
    expect(p).toContain('"verification_blockers"')
    expect(p).not.toContain('"new_candidates"')
    // The body must spell out the rule so future edits cannot re-add the
    // smuggling path SA used in the vuln_3 incident.
    expect(p).toContain("verification_blockers channel")
    expect(p).toContain("VH is the sole producer")
    expect(p).toContain("No vuln_candidates invention")
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
    expect(p).toContain("DO NOT: call `mcp__omp-db__patch_state`")
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

  test("spawn template forwards Knowledge paths consulted in Step 4 (K3 pre)", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    // SA forwards the absolute paths it actually lazy-read in Step 4 so
    // Exploiter can trust the list and skip its own catalog read.
    expect(p).toContain("Knowledge paths consulted")
    expect(p).toMatch(/paths YOU opened in Step 4/i)
    // Mentions the three category sources SA may lazy-read
    expect(p).toMatch(/ctf-pwn detail md|how2heap PoC|writeup\.md/)
    // Explicit "none" placeholder when SA opened nothing extra
    expect(p).toMatch(/or "none"/)
    // Anti-fabrication guard — list is empirical, not aspirational
    expect(p).toMatch(/Paths YOU did not open MUST NOT appear/i)
  })

  test("prompt emits recommended_mode hint with 2-way classification", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    // Step 5b classification rule exists (was Step 4b before K2잔여 renumber)
    expect(p).toContain("Step 5b")
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

  test("prompt encodes execution mode in the spawned agent name (T8/T9 cutover)", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    // Post-T8: the Exploiter is 4 mode-suffixed agents. SA resolves the
    // agent name from mode_override + recommended_mode; the agent name
    // itself encodes the execution mode (Mode 1/2/0/9). There is no
    // longer a "SA defers to Exploiter's mode choice" delegation.
    expect(p).toContain("omp-exploiter-mode-")
    expect(p).toContain("mode_override")
    // The spawned agent name encodes the mode — no in-prompt mode hint
    // override mechanic remains.
    expect(p).toMatch(/agent name (already )?encodes the mode/i)
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
    // workspace mount = the DB challenge_id (T21 unification — no derivation)
    expect(p).toContain('/workspace/<challenge_id>/')
    expect(p).toContain('DB challenge_id')
  })

  test("Key principles include Path forwarding rule", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    expect(p).toContain("Path forwarding only")
  })

  test("prompt has escalation policy on retry", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    // Step 4 default = lazy
    expect(p).toContain("Mode default: lazy")
    expect(p).toContain("escalation mode")
    // Round table — round 1 lazy, round 2-3 escalation ON
    expect(p).toContain("Round 1")
    expect(p).toContain("retries_used == 0")
    expect(p).toContain("resume #1")
    expect(p).toContain("Escalation ON")
    // Step 7 resume triggers revisit of Step 4 with escalation
    expect(p).toContain("escalation on resume")
    // User hint takes priority over the round mode
    expect(p).toContain("User hint")
  })

  test("prompt requires measurable expected_result with examples", () => {
    const agent = createOmpStrategistAgent("test-model")
    const p = agent.prompt ?? ""
    // Step 5 guideline
    expect(p).toContain("expected_result")
    expect(p).toContain("measurable")
    // ❌/✅ examples present
    expect(p).toContain("❌")
    expect(p).toContain("✅")
    // Step 6 prompt template carries the SPECIFIC measurable phrasing
    expect(p).toContain("SPECIFIC measurable observation")
  })

})
