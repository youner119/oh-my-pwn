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
      model: tool.schema
        .string()
        .optional()
        .describe(
          "Model for the sub-agent. Omit (or leave empty) → the agent's own " +
            "default model. 'parent' → inherit THIS (launching) session's " +
            "current model. Otherwise a 'providerID/modelID' string, e.g. " +
            "'openai/gpt-5.5' or 'anthropic/claude-opus-4-8'.",
        ),
    },
    async execute(
      args: {
        agent: string
        prompt: string
        description: string
        model?: string
      },
      ctx: { sessionID: string },
    ) {
      try {
        const result = await manager.launchAsync({
          parentSessionID: ctx.sessionID,
          agent: args.agent,
          description: args.description,
          prompt: args.prompt,
          modelSpec: args.model,
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
    async execute(args: { task_ids: string[] }, ctx: { abort?: AbortSignal }) {
      try {
        if (!Array.isArray(args.task_ids) || args.task_ids.length === 0) {
          return JSON.stringify({
            ok: false,
            error: "invalid_task_ids",
            message: "task_ids must be a non-empty array of strings",
          })
        }
        // Forward ctx.abort so an interrupted wait releases its manager-side
        // `done` listener instead of orphaning it (an orphan later eats a
        // task's submit — consumes + discards it — starving the next wait).
        const result = await manager.waitAll(args.task_ids, ctx?.abort)
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
    async execute(args: { task_ids: string[] }, ctx: { abort?: AbortSignal }) {
      try {
        if (!Array.isArray(args.task_ids) || args.task_ids.length === 0) {
          return JSON.stringify({
            ok: false,
            error: "invalid_task_ids",
            message: "task_ids must be a non-empty array of strings",
          })
        }
        // Forward ctx.abort — see wait_all: an orphaned listener from an
        // interrupted wait would consume + discard a later submit.
        const result = await manager.waitAny(args.task_ids, ctx?.abort)
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

/**
 * omp_task_submit — a sub-agent delivers its result (submit protocol, T41).
 *
 * Runs in the CHILD's session: the manager writes the result JSON to
 * `.omp/submissions/<session>-<cycle>.json` and appends a `task_submitted`
 * event. The parent harvests it via omp_task_wait_all / wait_any (which return
 * the parsed result). Submit is result-delivery only — it does NOT end the
 * worker (use omp_task_terminate when done).
 */
export function createOmpTaskSubmitTool(manager: BackgroundManager): ToolDefinition {
  return tool({
    description: `Submit your result (submit protocol). Deliver a JSON object; the parent harvests it via wait_all/wait_any.
Call once per turn when your result is ready. Submit is result delivery only — it does NOT end you. To end, call omp_task_terminate (or, if reusable, stay idle for the parent to resume/terminate).
You may submit multiple times across resumes (each is a distinct cycle).`,
    args: {
      result: tool.schema
        .record(tool.schema.string(), tool.schema.any())
        .describe("The result as a JSON object (e.g. { candidates: [...] } or { status, reason }). Success or failure both go here."),
    },
    async execute(args: { result: Record<string, unknown> }, ctx: { sessionID: string }) {
      try {
        const { cycle, result_path } = manager.submitResult(ctx.sessionID, args.result)
        return JSON.stringify({ ok: true, cycle, result_path })
      } catch (err) {
        return JSON.stringify({ ok: false, error: "submit_failed", message: String(err) })
      }
    },
  })
}

/**
 * omp_task_resume — re-prompt an idle worker with a follow-up (submit protocol,
 * T41). Parent-only (orchestrator / SA). The worker keeps its session context.
 */
export function createOmpTaskResumeTool(manager: BackgroundManager): ToolDefinition {
  return tool({
    description: `Resume an idle sub-agent with a follow-up prompt (submit protocol). The worker keeps its context.
Use to drive a reusable worker (e.g. an exploiter retry loop): after harvesting its submit, resume it with new instructions. Rejects terminal (terminated/failed/cancelled) tasks.`,
    args: {
      task_id: tool.schema.string().describe("Task ID of the idle worker to resume."),
      prompt: tool.schema.string().describe("Follow-up prompt for the worker."),
    },
    async execute(args: { task_id: string; prompt: string }) {
      try {
        const result = await manager.resume(args.task_id, args.prompt)
        return JSON.stringify({ ok: true, ...result })
      } catch (err) {
        return JSON.stringify({ ok: false, error: "resume_failed", message: String(err) })
      }
    },
  })
}

/**
 * omp_task_terminate — graceful close (submit protocol, T41). One tool, two
 * callers:
 *   - SELF-terminate (a sub-agent, no `task_id`): "I'm done." Appends a
 *     `task_terminated` event for its own session; the parent's poll teardown.
 *   - PARENT-terminate (orchestrator / SA, with `task_id`): end a reusable
 *     worker it's done with (e.g. exploiter after the retry budget).
 *
 * Distinct from omp_task_cancel (emergency abort): terminate does NOT abort the
 * session — it dies naturally.
 */
export function createOmpTaskTerminateTool(manager: BackgroundManager): ToolDefinition {
  return tool({
    description: `Gracefully end a worker (submit protocol). Two uses:
- SELF: call with NO task_id when you (a sub-agent) are done — after your final submit and any background work.
- PARENT: call with a task_id (orchestrator/SA) to end a reusable worker you're finished with (e.g. exploiter after retries).
Unlike omp_task_cancel (emergency abort), terminate lets the session end naturally.`,
    args: {
      task_id: tool.schema
        .string()
        .optional()
        .describe("Parent-terminate: the task to end. Omit for self-terminate (uses your own session)."),
    },
    async execute(args: { task_id?: string }, ctx: { sessionID: string }) {
      try {
        if (args.task_id) {
          const ok = manager.terminate(args.task_id)
          return JSON.stringify({ ok, mode: "parent", task_id: args.task_id })
        }
        manager.terminateSelf(ctx.sessionID)
        return JSON.stringify({ ok: true, mode: "self", session_id: ctx.sessionID })
      } catch (err) {
        return JSON.stringify({ ok: false, error: "terminate_failed", message: String(err) })
      }
    },
  })
}
