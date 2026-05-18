/**
 * omp_task — delegate work to sub-agents.
 *
 * Legacy 3-tool surface (sync wait, fire-and-forget+wait-all, race-pool):
 * - omp_task: single task (sync or background)
 * - omp_task_all: multiple tasks, wait for ALL results (VH ensemble, Reverser)
 * - omp_task_pool: multiple tasks with concurrency limit + early-exit (SA)
 *
 * New 4-tool surface (T7, additive — runs alongside legacy until T9 cutover):
 * - omp_task_launch:    fire-and-forget single task, returns {task_id, session_id}
 * - omp_task_wait_all:  wait for ALL of given task_ids to reach terminal
 * - omp_task_wait_any:  wait for ANY first complete + remaining_ids
 * - omp_task_cancel:    cancel given task_ids (best-effort, idempotent)
 *
 * The new tools split "fire" from "wait" so the LLM can dynamically spawn
 * follow-up tasks based on partial results — a pattern impossible under
 * the legacy `_pool`'s predicate-based atomic race.
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

        const maxConcurrency = args.max_concurrency ?? 5

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

/* ─────────────────────────────────────────────────────────────────────────── */
/* T7 — New 4-tool surface (additive, coexists with legacy until T9 cutover).  */
/* Spec: .omc/specs/deep-interview-omo-subagent-import.md                       */
/* ─────────────────────────────────────────────────────────────────────────── */

/**
 * omp_task_launch — fire-and-forget single sub-agent spawn.
 *
 * Returns immediately after the child opencode session is created and the
 * prompt is fired. Use omp_task_wait_all / wait_any to observe outcomes.
 */
export function createOmpTaskLaunchTool(manager: BackgroundManager): ToolDefinition {
  return tool({
    description: `Launch a sub-agent in fire-and-forget mode.
Returns { task_id, session_id } immediately; use omp_task_wait_all or omp_task_wait_any to observe outcomes.

Accepts a category alias (reverser / vulnhunter / strategist / exploiter) OR a direct agent name (omp-*).
Unknown names return an error.`,
    args: {
      agent: tool.schema
        .string()
        .describe(
          "Agent category (e.g., 'reverser', 'strategist') or full agent name (e.g., 'omp-reverser').",
        ),
      prompt: tool.schema.string().describe("Full prompt for the sub-agent."),
      description: tool.schema.string().describe("Short task description."),
    },
    async execute(
      args: { agent: string; prompt: string; description: string },
      ctx: { sessionID: string },
    ) {
      try {
        const result = await manager.launchAsync({
          parentSessionID: ctx.sessionID,
          agent: args.agent,
          description: args.description,
          prompt: args.prompt,
          runInBackground: true,
        })
        return JSON.stringify({
          ok: true,
          task_id: result.task_id,
          session_id: result.session_id,
        })
      } catch (err) {
        return JSON.stringify({
          ok: false,
          error: "launch_failed",
          message: String(err),
        })
      }
    },
  })
}

/**
 * omp_task_wait_all — wait for ALL given task_ids to reach terminal status.
 *
 * Results are returned in the same order as input task_ids. Unknown
 * task_ids are returned as synthetic failed outcomes (graceful — doesn't
 * block forever).
 */
export function createOmpTaskWaitAllTool(manager: BackgroundManager): ToolDefinition {
  return tool({
    description: `Wait until ALL given task_ids reach a terminal status (completed / failed / cancelled).
Results are returned in input order. Unknown task_ids are returned as synthetic failed outcomes (no infinite block).

Use for ensemble patterns where every result is needed (e.g., VH ensemble → merge).`,
    args: {
      task_ids: tool.schema
        .array(tool.schema.string())
        .describe("Task IDs from prior omp_task_launch calls."),
    },
    async execute(args: { task_ids: string[] }) {
      try {
        if (!Array.isArray(args.task_ids) || args.task_ids.length === 0) {
          return JSON.stringify({
            ok: false,
            error: "invalid_task_ids",
            message: "task_ids must be a non-empty array of strings",
          })
        }
        const result = await manager.waitAll(args.task_ids)
        return JSON.stringify({ ok: true, ...result })
      } catch (err) {
        return JSON.stringify({
          ok: false,
          error: "wait_all_failed",
          message: String(err),
        })
      }
    },
  })
}

/**
 * omp_task_wait_any — wait for the FIRST task_id to reach terminal status.
 *
 * Returns the first completer plus `remaining_ids` (input order preserved).
 * Re-call with `remaining_ids` to wait for the next completer. Cancel +
 * failure both count as first-complete (LLM decides what to do with the
 * result).
 */
export function createOmpTaskWaitAnyTool(manager: BackgroundManager): ToolDefinition {
  return tool({
    description: `Wait until ANY of the given task_ids reaches a terminal status (completed / failed / cancelled).
Returns the first completer + remaining_ids (input order preserved, first removed). Failure and cancellation BOTH count as first-complete — inspect status and decide.

Use for SA race + dynamic spawn patterns: launch×N → wait_any → analyze → cancel(remaining) or launch(extra).`,
    args: {
      task_ids: tool.schema
        .array(tool.schema.string())
        .describe("Task IDs from prior omp_task_launch calls."),
    },
    async execute(args: { task_ids: string[] }) {
      try {
        if (!Array.isArray(args.task_ids) || args.task_ids.length === 0) {
          return JSON.stringify({
            ok: false,
            error: "invalid_task_ids",
            message: "task_ids must be a non-empty array of strings",
          })
        }
        const result = await manager.waitAny(args.task_ids)
        return JSON.stringify({ ok: true, ...result })
      } catch (err) {
        return JSON.stringify({
          ok: false,
          error: "wait_any_failed",
          message: String(err),
        })
      }
    },
  })
}

/**
 * omp_task_cancel — best-effort cancel an array of task_ids.
 *
 * Idempotent: tasks that are unknown or already terminal end up in
 * `not_found`. cancelled tasks emit `done` so any pending wait_* picks
 * them up as first-complete.
 */
export function createOmpTaskCancelTool(manager: BackgroundManager): ToolDefinition {
  return tool({
    description: `Cancel an array of task_ids (best-effort, idempotent).
Returns { cancelled: [...], not_found: [...] }. Already-terminal or unknown ids end up in not_found.
Cancelled tasks emit a 'done' signal so any pending wait_* picks them up as first-complete.

Use after wait_any when you want to drop the remaining tasks (e.g., SA race early-exit).`,
    args: {
      task_ids: tool.schema
        .array(tool.schema.string())
        .describe("Task IDs to cancel."),
    },
    async execute(args: { task_ids: string[] }) {
      try {
        if (!Array.isArray(args.task_ids) || args.task_ids.length === 0) {
          return JSON.stringify({
            ok: false,
            error: "invalid_task_ids",
            message: "task_ids must be a non-empty array of strings",
          })
        }
        const cancelled: string[] = []
        const notFound: string[] = []
        for (const id of args.task_ids) {
          const ok = await manager.cancel(id)
          if (ok) cancelled.push(id)
          else notFound.push(id)
        }
        return JSON.stringify({
          ok: true,
          cancelled,
          not_found: notFound,
        })
      } catch (err) {
        return JSON.stringify({
          ok: false,
          error: "cancel_failed",
          message: String(err),
        })
      }
    },
  })
}
