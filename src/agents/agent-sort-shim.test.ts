import { describe, expect, test, beforeAll } from "bun:test"
import {
  OMP_AGENT_ORDER,
  reorderAgentsByPriority,
  installAgentSortShim,
} from "./agent-sort-shim"
import type { AgentConfig } from "./types"

const stubConfig = (description: string): AgentConfig =>
  ({ description, model: "stub", mode: "all" }) as AgentConfig

// All tests in this file activate the shim — install once before everything.
beforeAll(() => {
  installAgentSortShim()
})

describe("reorderAgentsByPriority", () => {
  test("places OMP_AGENT_ORDER entries first, in canonical order", () => {
    const input: Record<string, AgentConfig> = {
      "omp-exploiter": stubConfig("exploiter"),
      "omp-strategist": stubConfig("strategist"),
      "omp-vulnhunter": stubConfig("vh"),
      "omp-reverser": stubConfig("reverser"),
      "omp-orchestrator": stubConfig("orch"),
    }

    const result = reorderAgentsByPriority(input)

    expect(Object.keys(result)).toEqual([
      "omp-orchestrator",
      "omp-reverser",
      "omp-vulnhunter",
      "omp-strategist",
      "omp-exploiter",
    ])
  })

  test("injects `order` field starting at 1", () => {
    const input: Record<string, AgentConfig> = {
      "omp-orchestrator": stubConfig("orch"),
      "omp-reverser": stubConfig("reverser"),
    }

    const result = reorderAgentsByPriority(input) as Record<
      string,
      AgentConfig & { order?: number }
    >

    expect(result["omp-orchestrator"]?.order).toBe(1)
    expect(result["omp-reverser"]?.order).toBe(2)
  })

  test("preserves description on each config (only adds `order`)", () => {
    const input: Record<string, AgentConfig> = {
      "omp-orchestrator": stubConfig("orch-desc"),
    }
    const result = reorderAgentsByPriority(input)
    expect(result["omp-orchestrator"]?.description).toBe("orch-desc")
  })

  test("places unknown agents alphabetically after OMP order", () => {
    const input: Record<string, AgentConfig> = {
      "zeta-agent": stubConfig("z"),
      "alpha-agent": stubConfig("a"),
      "omp-orchestrator": stubConfig("orch"),
      "omp-reverser": stubConfig("reverser"),
      "middle-agent": stubConfig("m"),
    }

    expect(Object.keys(reorderAgentsByPriority(input))).toEqual([
      "omp-orchestrator",
      "omp-reverser",
      "alpha-agent",
      "middle-agent",
      "zeta-agent",
    ])
  })

  test("handles partial subsets (missing OMP agents)", () => {
    const input: Record<string, AgentConfig> = {
      "omp-exploiter": stubConfig("exploiter"),
      "omp-orchestrator": stubConfig("orch"),
    }
    expect(Object.keys(reorderAgentsByPriority(input))).toEqual([
      "omp-orchestrator",
      "omp-exploiter",
    ])
  })

  test("does not mutate the input map", () => {
    const input: Record<string, AgentConfig> = {
      "omp-exploiter": stubConfig("exploiter"),
      "omp-orchestrator": stubConfig("orch"),
    }
    const originalKeys = Object.keys(input)
    reorderAgentsByPriority(input)
    expect(Object.keys(input)).toEqual(originalKeys)
  })

  test("returns empty object for empty input", () => {
    expect(reorderAgentsByPriority({})).toEqual({})
  })
})

describe("installAgentSortShim — agent arrays are reordered", () => {
  test("Array.sort on agent objects respects OMP_AGENT_ORDER", () => {
    const arr = [
      { name: "omp-exploiter" },
      { name: "omp-orchestrator" },
      { name: "omp-vulnhunter" },
      { name: "omp-reverser" },
      { name: "omp-strategist" },
    ]
    // opencode's actual call uses sortBy which boils down to sort with a
    // string comparator on name. Simulate that.
    arr.sort((a, b) => a.name.localeCompare(b.name))
    expect(arr.map((a) => a.name)).toEqual([
      "omp-orchestrator",
      "omp-reverser",
      "omp-vulnhunter",
      "omp-strategist",
      "omp-exploiter",
    ])
  })

  test("Array.toSorted on agent objects respects OMP_AGENT_ORDER", () => {
    const arr = [
      { name: "omp-strategist" },
      { name: "omp-orchestrator" },
      { name: "omp-exploiter" },
    ]
    const sorted = arr.toSorted((a, b) => a.name.localeCompare(b.name))
    expect(sorted.map((a) => a.name)).toEqual([
      "omp-orchestrator",
      "omp-strategist",
      "omp-exploiter",
    ])
  })

  test("unknown agents fall through to the caller's comparator", () => {
    const arr = [
      { name: "zeta-agent" },
      { name: "alpha-agent" },
      { name: "omp-orchestrator" },
      { name: "omp-reverser" },
    ]
    arr.sort((a, b) => a.name.localeCompare(b.name))
    // OMP-ranked names come first; the two unknowns keep alphabetical order.
    expect(arr.map((a) => a.name)).toEqual([
      "omp-orchestrator",
      "omp-reverser",
      "alpha-agent",
      "zeta-agent",
    ])
  })
})

describe("installAgentSortShim — non-agent arrays use native sort", () => {
  test("string arrays sort alphabetically as before", () => {
    const arr = ["c", "a", "b"]
    arr.sort()
    expect(arr).toEqual(["a", "b", "c"])
  })

  test("number arrays sort numerically when given a comparator", () => {
    const arr = [10, 2, 30]
    arr.sort((a, b) => a - b)
    expect(arr).toEqual([2, 10, 30])
  })

  test("objects without name are not treated as agents", () => {
    const arr = [
      { id: "c", val: 3 },
      { id: "a", val: 1 },
      { id: "b", val: 2 },
    ]
    arr.sort((a, b) => a.id.localeCompare(b.id))
    expect(arr.map((x) => x.id)).toEqual(["a", "b", "c"])
  })

  test("agent-shaped array of size 1 uses native behavior", () => {
    const arr = [{ name: "omp-orchestrator" }]
    arr.sort((a, b) => a.name.localeCompare(b.name))
    expect(arr).toEqual([{ name: "omp-orchestrator" }])
  })

  test("array with only one ranked element uses native behavior", () => {
    // 1 ranked + 1 unknown → rankedHits < 2 → native sort
    const arr = [
      { name: "zeta-agent" },
      { name: "omp-orchestrator" },
    ]
    arr.sort((a, b) => a.name.localeCompare(b.name))
    expect(arr.map((a) => a.name)).toEqual([
      "omp-orchestrator",
      "zeta-agent",
    ])
  })

  test("mixed array with null short-circuits to native", () => {
    const arr = [{ name: "omp-orchestrator" }, null, { name: "omp-exploiter" }]
    // Native sort with default comparator: null is coerced to string; result
    // varies, but must not throw. Just assert no exception + length preserved.
    expect(() =>
      arr.sort((a, b) => {
        const aName = (a as { name?: string } | null)?.name ?? ""
        const bName = (b as { name?: string } | null)?.name ?? ""
        return aName.localeCompare(bName)
      }),
    ).not.toThrow()
    expect(arr.length).toBe(3)
  })
})

describe("installAgentSortShim — idempotency", () => {
  test("calling installAgentSortShim multiple times is safe", () => {
    installAgentSortShim()
    installAgentSortShim()
    installAgentSortShim()

    const arr = [{ name: "omp-exploiter" }, { name: "omp-orchestrator" }]
    arr.sort((a, b) => a.name.localeCompare(b.name))
    expect(arr.map((a) => a.name)).toEqual([
      "omp-orchestrator",
      "omp-exploiter",
    ])
  })
})

describe("OMP_AGENT_ORDER", () => {
  test("starts with omp-orchestrator (picker default)", () => {
    expect(OMP_AGENT_ORDER[0]).toBe("omp-orchestrator")
  })

  test("contains all 5 OmP agents with no duplicates", () => {
    expect(OMP_AGENT_ORDER.length).toBe(5)
    expect(new Set(OMP_AGENT_ORDER).size).toBe(5)
  })
})
