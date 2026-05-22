import { describe, expect, test } from "bun:test"
import { CATEGORY_MAP, resolveAgent } from "./agent-resolver"

describe("resolveAgent — category aliases", () => {
  test("'setup' → omp-setup (envsetup 재설계 T10/T11)", () => {
    expect(resolveAgent("setup")).toBe("omp-setup")
  })

  test("'reverser' → omp-reverser", () => {
    expect(resolveAgent("reverser")).toBe("omp-reverser")
  })

  test("'vulnhunter' → omp-vulnhunter", () => {
    expect(resolveAgent("vulnhunter")).toBe("omp-vulnhunter")
  })

  test("'strategist' → omp-strategist", () => {
    expect(resolveAgent("strategist")).toBe("omp-strategist")
  })

  test("'exploiter' short alias removed — must use mode-suffixed name", () => {
    expect(() => resolveAgent("exploiter")).toThrow(
      /unknown agent or category/,
    )
  })
})

describe("resolveAgent — direct agent name passthrough", () => {
  test("omp-setup passes through (envsetup 재설계 T10/T11)", () => {
    expect(resolveAgent("omp-setup")).toBe("omp-setup")
  })

  test("omp-reverser passes through", () => {
    expect(resolveAgent("omp-reverser")).toBe("omp-reverser")
  })

  test("omp-vulnhunter passes through", () => {
    expect(resolveAgent("omp-vulnhunter")).toBe("omp-vulnhunter")
  })

  test("omp-strategist passes through", () => {
    expect(resolveAgent("omp-strategist")).toBe("omp-strategist")
  })

  test("omp-exploiter-mode-1 passes through", () => {
    expect(resolveAgent("omp-exploiter-mode-1")).toBe("omp-exploiter-mode-1")
  })

  test("omp-exploiter-mode-2 passes through", () => {
    expect(resolveAgent("omp-exploiter-mode-2")).toBe("omp-exploiter-mode-2")
  })

  test("omp-exploiter-mode-0 passes through", () => {
    expect(resolveAgent("omp-exploiter-mode-0")).toBe("omp-exploiter-mode-0")
  })

  test("omp-exploiter-mode-9 passes through", () => {
    expect(resolveAgent("omp-exploiter-mode-9")).toBe("omp-exploiter-mode-9")
  })

  test("bare omp-exploiter (no mode suffix) throws", () => {
    expect(() => resolveAgent("omp-exploiter")).toThrow(
      /unknown agent or category/,
    )
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
  test("exposes 4 categories: setup, reverser, vulnhunter, strategist (exploiter removed in T8 cutover)", () => {
    expect(Object.keys(CATEGORY_MAP).sort()).toEqual([
      "reverser",
      "setup",
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
