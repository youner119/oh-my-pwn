import { describe, expect, test } from "bun:test"
import { createOmpReverserAgent } from "./omp-reverser"

describe("createOmpReverserAgent", () => {
  test("creates agent with subagent mode", () => {
    expect(createOmpReverserAgent.mode).toBe("subagent")
  })

  test("has description", () => {
    const agent = createOmpReverserAgent("test-model")
    expect(agent.description).toBeTruthy()
    expect(typeof agent.description).toBe("string")
    expect((agent.description as string).length).toBeGreaterThan(0)
  })

  test("prompt contains dangerous function knowledge", () => {
    const agent = createOmpReverserAgent("test-model")
    expect(agent.prompt).toContain("gets")
    expect(agent.prompt).toContain("stack BOF")
  })

  test("prompt mentions ghidra-mcp tools", () => {
    const agent = createOmpReverserAgent("test-model")
    expect(agent.prompt).toContain("decompile_function")
    expect(agent.prompt).toContain("list_functions_enhanced")
  })

  test("prompt mentions analysis output format", () => {
    const agent = createOmpReverserAgent("test-model")
    expect(agent.prompt).toContain("reverser-analysis.json")
  })

  test("prompt mentions source-present mode", () => {
    const agent = createOmpReverserAgent("test-model")
    expect(agent.prompt).toContain("source")
    expect(agent.prompt?.toLowerCase()).toContain("skip")
  })
})
