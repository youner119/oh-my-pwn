import { describe, expect, test } from "bun:test"
import {
  DANGEROUS_FUNCTION_REASONS,
  DANGEROUS_FUNCTIONS,
  formatDangerousFunctionsForPrompt,
} from "./constants"

describe("DANGEROUS_FUNCTION_REASONS", () => {
  test("contains expected dangerous functions", () => {
    expect(DANGEROUS_FUNCTION_REASONS).toHaveProperty("gets")
    expect(DANGEROUS_FUNCTION_REASONS).toHaveProperty("printf")
    expect(DANGEROUS_FUNCTION_REASONS).toHaveProperty("system")
    expect(DANGEROUS_FUNCTION_REASONS).toHaveProperty("free")
    expect(DANGEROUS_FUNCTION_REASONS).toHaveProperty("malloc")
  })

  test("all reasons are non-empty strings", () => {
    for (const [fn, reason] of Object.entries(DANGEROUS_FUNCTION_REASONS)) {
      expect(typeof reason).toBe("string")
      expect(reason.length).toBeGreaterThan(0)
      void fn
    }
  })

  test("DANGEROUS_FUNCTIONS set matches DANGEROUS_FUNCTION_REASONS keys", () => {
    const reasonKeys = new Set(Object.keys(DANGEROUS_FUNCTION_REASONS))
    expect(DANGEROUS_FUNCTIONS.size).toBe(reasonKeys.size)
    for (const fn of reasonKeys) {
      expect(DANGEROUS_FUNCTIONS.has(fn)).toBe(true)
    }
    for (const fn of DANGEROUS_FUNCTIONS) {
      expect(reasonKeys.has(fn)).toBe(true)
    }
  })
})

describe("formatDangerousFunctionsForPrompt", () => {
  test("returns a markdown table", () => {
    const output = formatDangerousFunctionsForPrompt()
    expect(output).toContain("| Function |")
    expect(output).toContain("|---|")
    expect(output).toContain("`gets`")
  })

  test("entries are sorted alphabetically", () => {
    const output = formatDangerousFunctionsForPrompt()
    const lines = output.split("\n")
    // Skip header line and separator line
    const dataLines = lines.slice(2)
    const functionNames = dataLines.map((line) => {
      const match = line.match(/\| `([^`]+)` \|/)
      return match ? match[1] : ""
    })
    const sorted = [...functionNames].sort((a, b) => a.localeCompare(b))
    expect(functionNames).toEqual(sorted)
  })
})
