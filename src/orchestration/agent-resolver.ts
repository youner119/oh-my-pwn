/**
 * Category → agent name resolution for omp_task_launch.
 *
 * Lets the orchestrator prompt reference agents by short category
 * (e.g., "reverser") instead of full agent name. Direct agent names
 * (e.g., "omp-reverser") pass through unchanged. Unknown names throw.
 *
 * Exploiter has **no short category alias** (post `mode-0-9-setup` T8
 * cutover). The Orchestrator must pass an explicit mode-suffixed name
 * — `omp-exploiter-mode-1` / `-mode-2` / `-mode-0` / `-mode-9` —
 * because the dispatch choice is part of the spawn semantics, not a
 * resolver convenience.
 */

export const CATEGORY_MAP = {
  setup: "omp-setup",
  reverser: "omp-reverser",
  vulnhunter: "omp-vulnhunter",
  strategist: "omp-strategist",
} as const

const KNOWN_AGENTS: ReadonlySet<string> = new Set([
  ...Object.values(CATEGORY_MAP),
  "omp-exploiter-mode-1",
  "omp-exploiter-mode-2",
  "omp-exploiter-mode-0",
  "omp-exploiter-mode-9",
  // GPT/principle-driven prompt variants (decisions.md #5). Launched by
  // explicit name only — no category alias, same as their siblings.
  "omp-exploiter-mode-1-gpt",
  "omp-exploiter-mode-2-gpt",
])

/**
 * Resolve a category alias or direct agent name to a concrete agent name.
 *
 * - category match (e.g., "reverser") → mapped agent name
 * - known agent name (e.g., "omp-reverser") → as-is
 * - anything else → throws with a message listing valid choices
 */
export function resolveAgent(name: string): string {
  if (!name) {
    throw new Error("resolveAgent: name must be a non-empty string")
  }
  if (name in CATEGORY_MAP) {
    return CATEGORY_MAP[name as keyof typeof CATEGORY_MAP]
  }
  if (KNOWN_AGENTS.has(name)) {
    return name
  }
  throw new Error(
    `resolveAgent: unknown agent or category "${name}". ` +
      `Valid categories: ${Object.keys(CATEGORY_MAP).join(", ")}. ` +
      `Valid agents: ${Array.from(KNOWN_AGENTS).join(", ")}.`,
  )
}
