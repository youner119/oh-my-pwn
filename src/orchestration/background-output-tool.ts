/**
 * omp_background_output — retrieve results from a background task.
 *
 * After launching a task with omp_task(run_in_background=true), call this
 * tool with the task_id to check status and retrieve the sub-agent's output.
 */

import type { ToolDefinition } from "@opencode-ai/plugin/tool"
import { tool } from "@opencode-ai/plugin/tool"
import type { BackgroundManager } from "./background-manager"

export function createOmpBackgroundOutputTool(
  manager: BackgroundManager,
): ToolDefinition {
  return tool({
    description: `Retrieve the result of a background task launched by omp_task.

Returns the task status and, if completed, the sub-agent's full output.
If the task is still running, returns status "running" — call again later.

Use this after launching tasks with omp_task(run_in_background=true).`,
    args: {
      task_id: tool.schema
        .string()
        .describe("The task_id returned by omp_task when run_in_background=true."),
    },
    async execute(args: { task_id: string }) {
      try {
        const result = await manager.getResult(args.task_id)

        return JSON.stringify({
          ok: result.status === "completed",
          task_id: result.taskId,
          status: result.status,
          ...(result.output !== undefined ? { output: result.output } : {}),
          ...(result.error ? { error: result.error } : {}),
        })
      } catch (err) {
        return JSON.stringify({
          error: "output_fetch_failed",
          message: String(err),
        })
      }
    },
  })
}
