/**
 * Agent sort shim for opencode TUI picker.
 *
 * opencode 1.4.x ignores the agent `order` field (sst/opencode#19127) and
 * sorts agents alphabetically by name via Remeda `sortBy(x => x.name, "asc")`
 * at packages/opencode/src/agent/agent.ts. Without intervention this makes
 * `omp-exploiter` the first picker entry — wrong for OmP, where users almost
 * always want to start a session with `omp-orchestrator`.
 *
 * Two complementary layers, both required:
 *
 * 1. `reorderAgentsByPriority` — declarative reorder of the cfg.agent record
 *    plus injection of `order: N` into each AgentConfig (future-proof for
 *    when #19127 ships; harmless until then).
 * 2. `installAgentSortShim` — narrow monkey-patch of `Array.prototype.sort`
 *    and `Array.prototype.toSorted`. Detects agent arrays (≥2 elements whose
 *    `.name` matches an OMP_AGENT_ORDER entry) and applies OMP rank before
 *    falling back to the caller-provided comparator. Non-agent arrays pass
 *    through to native behavior unchanged.
 *
 * The shim runs in the plugin's V8 context, which opencode shares — that's
 * why patching Array.prototype here reaches opencode's internal sort call.
 *
 * Pattern adapted from references/oh-my-openagent/src/shared/agent-sort-shim.ts
 * (sisyphus → hephaestus → prometheus → atlas), simplified for OmP's flat
 * config-key-as-display-name model.
 *
 * Remove this shim once opencode honors the agent `order` field.
 */

import type { AgentConfig } from "./types"

/**
 * OmP canonical agent order for the opencode TUI picker.
 * Index 0 = picker default (first entry).
 */
export const OMP_AGENT_ORDER = [
  "omp-orchestrator",
  "omp-setup",
  "omp-reverser",
  "omp-vulnhunter",
  "omp-strategist",
  "omp-exploiter-mode-1",
  "omp-exploiter-mode-2",
  "omp-exploiter-mode-0",
  "omp-exploiter-mode-9",
] as const

const OMP_AGENT_RANK: ReadonlyMap<string, number> = new Map(
  OMP_AGENT_ORDER.map((name, index) => [name, index + 1]),
)

const OMP_AGENT_NAMES: ReadonlySet<string> = new Set(OMP_AGENT_ORDER)

const UNRANKED = Number.MAX_SAFE_INTEGER

/**
 * Reorder a cfg.agent map so OMP_AGENT_ORDER entries come first (in order),
 * followed by every other key sorted alphabetically. Each AgentConfig also
 * gets an `order: N` field injected — opencode 1.4.x ignores it, but it
 * future-proofs for when #19127 ships.
 *
 * Non-OmP entries (e.g. user-added agents in opencode.json) preserve their
 * shape and just receive the alphabetical tail position.
 */
export function reorderAgentsByPriority(
  agents: Record<string, AgentConfig | undefined>,
): Record<string, AgentConfig | undefined> {
  const reordered: Record<string, AgentConfig | undefined> = {}
  const placed = new Set<string>()

  for (const [index, name] of OMP_AGENT_ORDER.entries()) {
    if (Object.prototype.hasOwnProperty.call(agents, name)) {
      const config = agents[name]
      reordered[name] = injectOrderField(config, index + 1)
      placed.add(name)
    }
  }

  const tail = Object.keys(agents)
    .filter((key) => !placed.has(key))
    .sort((a, b) => a.localeCompare(b))

  for (const key of tail) {
    reordered[key] = agents[key]
  }

  return reordered
}

function injectOrderField(
  config: AgentConfig | undefined,
  order: number,
): AgentConfig | undefined {
  if (!config || typeof config !== "object") return config
  return { ...config, order } as AgentConfig
}

function extractAgentName(value: unknown): string {
  if (value === null || typeof value !== "object") return ""
  const candidate = value as { name?: unknown }
  return typeof candidate.name === "string" ? candidate.name : ""
}

/**
 * Heuristic: an "agent array" has ≥2 elements, every element is an object
 * with a string `.name`, and ≥2 of those names are OMP-ranked. This avoids
 * accidentally biasing unrelated `.sort()` calls (string arrays, number
 * arrays, plain objects, etc.).
 */
function isOmpAgentArray(arr: ReadonlyArray<unknown>): boolean {
  if (arr.length < 2) return false
  let rankedHits = 0
  for (const element of arr) {
    if (element === null || typeof element !== "object") return false
    const name = (element as { name?: unknown }).name
    if (typeof name !== "string") return false
    if (OMP_AGENT_NAMES.has(name)) rankedHits++
  }
  return rankedHits >= 2
}

function compareByOmpRank(
  a: unknown,
  b: unknown,
  fallback: ((a: unknown, b: unknown) => number) | undefined,
): number {
  const aRank = OMP_AGENT_RANK.get(extractAgentName(a)) ?? UNRANKED
  const bRank = OMP_AGENT_RANK.get(extractAgentName(b)) ?? UNRANKED
  if (aRank !== bRank) return aRank - bRank
  if (fallback) return fallback(a, b)
  return 0
}

let installed = false

/**
 * Install Array.prototype.{sort,toSorted} patches. Idempotent — calling
 * multiple times is a no-op after the first.
 *
 * Must be called at module load time, before opencode's agent.ts runs its
 * sortBy. plugin.ts calls this at top-level import, which is the right
 * place.
 */
export function installAgentSortShim(): void {
  if (installed) return

  const originalToSorted = Array.prototype.toSorted
  const originalSort = Array.prototype.sort

  function patchedToSorted(
    this: unknown[],
    compareFn?: (a: unknown, b: unknown) => number,
  ): unknown[] {
    if (isOmpAgentArray(this)) {
      return originalToSorted.call(this, (a, b) =>
        compareByOmpRank(a, b, compareFn),
      )
    }
    return originalToSorted.call(this, compareFn)
  }

  function patchedSort(
    this: unknown[],
    compareFn?: (a: unknown, b: unknown) => number,
  ): unknown[] {
    if (isOmpAgentArray(this)) {
      return originalSort.call(this, (a, b) => compareByOmpRank(a, b, compareFn))
    }
    return originalSort.call(this, compareFn)
  }

  Object.defineProperty(Array.prototype, "toSorted", {
    value: patchedToSorted,
    configurable: true,
    writable: true,
    enumerable: false,
  })
  Object.defineProperty(Array.prototype, "sort", {
    value: patchedSort,
    configurable: true,
    writable: true,
    enumerable: false,
  })

  installed = true
}
