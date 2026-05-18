/**
 * Sub-agent delegation tools — 4-tool surface.
 *
 * Spec: `.omc/specs/deep-interview-omo-subagent-import.md`
 *
 * - omp_task_launch:    fire-and-forget single task, returns {task_id, session_id}
 * - omp_task_wait_all:  wait for ALL of given task_ids to reach terminal
 * - omp_task_wait_any:  wait for ANY first complete + remaining_ids
 * - omp_task_cancel:    cancel given task_ids (best-effort, idempotent)
 *
 * Splitting "fire" from "wait" lets the LLM dynamically spawn follow-up
 * tasks based on partial results — a pattern impossible under the
 * previous predicate-based atomic race tool.
 */

import type { ToolDefinition } from "@opencode-ai/plugin/tool"
import { tool } from "@opencode-ai/plugin/tool"
import type { BackgroundManager } from "./background-manager"

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
