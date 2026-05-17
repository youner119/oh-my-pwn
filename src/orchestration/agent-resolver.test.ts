import { describe, expect, test } from "bun:test"
import { CATEGORY_MAP, resolveAgent } from "./agent-resolver"

describe("resolveAgent — category aliases", () => {
  test("'reverser' → omp-reverser", () => {
    expect(resolveAgent("reverser")).toBe("omp-reverser")
  })

  test("'vulnhunter' → omp-vulnhunter", () => {
    expect(resolveAgent("vulnhunter")).toBe("omp-vulnhunter")
  })

  test("'strategist' → omp-strategist", () => {
    expect(resolveAgent("strategist")).toBe("omp-strategist")
  })

  test("'exploiter' → omp-exploiter", () => {
    expect(resolveAgent("exploiter")).toBe("omp-exploiter")
  })
})

describe("resolveAgent — direct agent name passthrough", () => {
  test("omp-reverser passes through", () => {
    expect(resolveAgent("omp-reverser")).toBe("omp-reverser")
  })

  test("omp-vulnhunter passes through", () => {
    expect(resolveAgent("omp-vulnhunter")).toBe("omp-vulnhunter")
  })

  test("omp-strategist passes through", () => {
    expect(resolveAgent("omp-strategist")).toBe("omp-strategist")
  })

  test("omp-exploiter passes through", () => {
    expect(resolveAgent("omp-exploiter")).toBe("omp-exploiter")
  })
})

describe("resolveAgent — error cases", () => {
  test("unknown name throws", () => {
    expect(() => resolveAgent("not-real")).toThrow(/unknown agent or category/)
  })

  test("error message lists valid categories and agents", () => {
    try {
      resolveAgent("xxx")
      throw new Error("did not throw")
    } catch (e) {
      const msg = String((e as Error).message)
      expect(msg).toContain("reverser")
      expect(msg).toContain("omp-reverser")
    }
  })

  test("case-sensitive: 'Reverser' (capital R) throws", () => {
    expect(() => resolveAgent("Reverser")).toThrow(/unknown agent or category/)
  })

  test("case-sensitive: 'OMP-REVERSER' throws", () => {
    expect(() => resolveAgent("OMP-REVERSER")).toThrow(/unknown agent or category/)
  })

  test("empty string throws", () => {
    expect(() => resolveAgent("")).toThrow(/non-empty/)
  })

  test("typo near category throws", () => {
    expect(() => resolveAgent("reverer")).toThrow(/unknown agent or category/)
  })
})

describe("CATEGORY_MAP — shape", () => {
  test("exposes 4 categories: reverser, vulnhunter, strategist, exploiter", () => {
    expect(Object.keys(CATEGORY_MAP).sort()).toEqual([
      "exploiter",
      "reverser",
      "strategist",
      "vulnhunter",
    ])
  })

  test("every category maps to its omp-* agent", () => {
    for (const [category, agent] of Object.entries(CATEGORY_MAP)) {
      expect(agent).toBe(`omp-${category}`)
    }
  })
})
