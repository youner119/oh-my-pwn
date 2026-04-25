/**
 * omp_task — delegate work to sub-agents.
 *
 * Three modes:
 * - omp_task: single task (sync or background)
 * - omp_task_all: multiple tasks, wait for ALL results (VH ensemble, Reverser)
 * - omp_task_pool: multiple tasks with concurrency limit + early-exit (SA)
 */

import type { ToolDefinition } from "@opencode-ai/plugin/tool"
import { tool } from "@opencode-ai/plugin/tool"
import type { BackgroundManager } from "./background-manager"

/**
 * omp_task — single sub-agent delegation (sync or background).
 * Used by SA → Exploiter (sync).
 */
export function createOmpTaskTool(manager: BackgroundManager): ToolDefinition {
  return tool({
    description: `Delegate work to a single OmP sub-agent. Blocks until the sub-agent finishes and returns the result.

Available agents: omp-vulnhunter, omp-strategist, omp-exploiter, omp-reverser.

For parallel execution of MULTIPLE tasks, use omp_task_all (wait for all) or omp_task_pool (early-exit on flag).`,
    args: {
      agent: tool.schema.string().describe("Agent name (e.g., 'omp-exploiter')."),
      prompt: tool.schema.string().describe("Full prompt for the sub-agent."),
      description: tool.schema.string().describe("Short task description."),
    },
    async execute(
      args: { agent: string; prompt: string; description: string },
      ctx: { sessionID: string },
    ) {
      try {
        const result = await manager.launch({
          parentSessionID: ctx.sessionID,
          agent: args.agent,
          description: args.description,
          prompt: args.prompt,
          runInBackground: false,
        })
        return JSON.stringify({
          ok: result.status === "completed",
          task_id: result.taskId,
          status: result.status,
          output: result.output ?? "",
          ...(result.error ? { error: result.error } : {}),
        })
      } catch (err) {
        return JSON.stringify({ error: "task_failed", message: String(err) })
      }
    },
  })
}

/**
 * omp_task_all — launch multiple sub-agents in parallel, wait for ALL.
 * Used by Orchestrator for VH ensemble and Reverser.
 */
export function createOmpTaskAllTool(manager: BackgroundManager): ToolDefinition {
  return tool({
    description: `Launch multiple sub-agents in parallel and wait for ALL to complete.

Use for VH ensemble (all results needed for merge) and single-agent tasks like Reverser.

Pass a JSON array of tasks. Each task has: agent, prompt, description.
Returns an array of results in the same order.`,
    args: {
      tasks: tool.schema.string().describe(
        'JSON array of tasks. Example: [{"agent":"omp-vulnhunter","prompt":"...","description":"VH-1"}, ...]',
      ),
    },
    async execute(
      args: { tasks: string },
      ctx: { sessionID: string },
    ) {
      try {
        const parsed = JSON.parse(args.tasks) as Array<{
          agent: string
          prompt: string
          description: string
        }>

        if (!Array.isArray(parsed) || parsed.length === 0) {
          return JSON.stringify({ error: "invalid_tasks", message: "tasks must be a non-empty JSON array" })
        }

        const inputs = parsed.map((t) => ({
          parentSessionID: ctx.sessionID,
          agent: t.agent,
          prompt: t.prompt,
          description: t.description,
          runInBackground: false as const,
        }))

        const results = await manager.launchAll(inputs)

        return JSON.stringify({
          ok: true,
          mode: "wait-all",
          count: results.length,
          results: results.map((r) => ({
            task_id: r.taskId,
            status: r.status,
            output: r.output ?? "",
            ...(r.error ? { error: r.error } : {}),
          })),
        })
      } catch (err) {
        return JSON.stringify({ error: "task_all_failed", message: String(err) })
      }
    },
  })
}

/**
 * omp_task_pool — launch tasks with concurrency limit + early-exit on flag.
 * Used by Orchestrator for SA+Exploiter parallel execution.
 */
export function createOmpTaskPoolTool(manager: BackgroundManager): ToolDefinition {
  return tool({
    description: `Launch multiple sub-agents with a concurrency limit. Stops early if any result contains a flag.

Use for SA+Exploiter parallel execution. Max N tasks run simultaneously.
When one finishes, the next starts from the queue. If any result contains
a non-null "flag" field, remaining tasks are skipped.

Pass a JSON array of tasks and max_concurrency.
Returns collected results (may be partial if early-exit triggered).`,
    args: {
      tasks: tool.schema.string().describe(
        'JSON array of tasks. Each: {"agent":"omp-strategist","prompt":"...","description":"SA-1"}',
      ),
      max_concurrency: tool.schema
        .number()
        .optional()
        .describe("Max simultaneous tasks. Default 3."),
    },
    async execute(
      args: { tasks: string; max_concurrency?: number },
      ctx: { sessionID: string },
    ) {
      try {
        const parsed = JSON.parse(args.tasks) as Array<{
          agent: string
          prompt: string
          description: string
        }>

        if (!Array.isArray(parsed) || parsed.length === 0) {
          return JSON.stringify({ error: "invalid_tasks", message: "tasks must be a non-empty JSON array" })
        }

        const inputs = parsed.map((t) => ({
          parentSessionID: ctx.sessionID,
          agent: t.agent,
          prompt: t.prompt,
          description: t.description,
          runInBackground: false as const,
        }))

        const maxConcurrency = args.max_concurrency ?? 3

        const { results, flagFound } = await manager.launchPool(
          inputs,
          maxConcurrency,
          (r) => {
            if (!r.output) return false
            try {
              const parsed = JSON.parse(r.output)
              return parsed.flag != null
            } catch {
              return r.output.includes('"flag"') && !r.output.includes('"flag": null')
            }
          },
        )

        return JSON.stringify({
          ok: true,
          mode: "early-exit-pool",
          flag_found: flagFound,
          completed: results.length,
          total: parsed.length,
          results: results.map((r) => ({
            task_id: r.taskId,
            status: r.status,
            output: r.output ?? "",
            ...(r.error ? { error: r.error } : {}),
          })),
        })
      } catch (err) {
        return JSON.stringify({ error: "task_pool_failed", message: String(err) })
      }
    },
  })
}
