import { describe, expect, test } from "bun:test"

import {
  createOmpTaskSubmitTool,
  createOmpTaskTerminateTool,
} from "./task-tool"
import type { BackgroundManager } from "./background-manager"

describe("omp_task_terminate tool dispatch (T41)", () => {
  test("task_id → parent-terminate; no task_id → self-terminate (ctx.sessionID)", async () => {
    const calls: string[] = []
    const manager = {
      terminate: (id: string) => {
        calls.push(`parent:${id}`)
        return true
      },
      terminateSelf: (sid: string) => {
        calls.push(`self:${sid}`)
      },
    } as unknown as BackgroundManager

    const tool = createOmpTaskTerminateTool(manager)
    await tool.execute({ task_id: "t1" }, { sessionID: "s1" } as never)
    await tool.execute({}, { sessionID: "s1" } as never)

    expect(calls).toEqual(["parent:t1", "self:s1"])
  })
})

describe("omp_task_submit tool (T41)", () => {
  test("delegates result to submitResult with the caller's sessionID", async () => {
    let seen: { sessionId?: string; result?: unknown } = {}
    const manager = {
      submitResult: (sessionId: string, result: unknown) => {
        seen = { sessionId, result }
        return { cycle: 1, result_path: "/x-1.json" }
      },
    } as unknown as BackgroundManager

    const tool = createOmpTaskSubmitTool(manager)
    const out = await tool.execute({ result: { status: "ok" } }, { sessionID: "s9" } as never)

    expect(seen.sessionId).toBe("s9")
    expect(seen.result).toEqual({ status: "ok" })
    expect(JSON.parse(out as string)).toMatchObject({ ok: true, cycle: 1 })
  })
})
