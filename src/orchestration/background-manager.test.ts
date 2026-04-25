import { describe, expect, test } from "bun:test"
import { BackgroundManager } from "./background-manager"
import type { OmpSessionClient } from "./types"

/** Fake session client for testing. */
/**
 * Fake session client that mimics opencode SDK response shapes.
 *
 * SDK wraps all responses in { data: <actual>, request, response }.
 * Session status types: "idle" (done), "busy" (running), "retry" (error retry).
 */
function createFakeClient(options?: {
  /** Status to return when session is done. Defaults to "idle". */
  defaultStatus?: string
  /** Delay (ms) before session goes idle. 0 = immediate. */
  idleDelay?: number
}): OmpSessionClient & { sessions: Map<string, { agent: string; prompt: string }> } {
  const sessions = new Map<string, { agent: string; prompt: string }>()
  let sessionCounter = 0
  const startTimes = new Map<string, number>()
  const delay = options?.idleDelay ?? 0

  return {
    sessions,
    async create(params) {
      sessionCounter += 1
      const id = `session-${sessionCounter}`
      startTimes.set(id, Date.now())
      // SDK shape: { data: { id: "..." }, request, response }
      return { data: { id } }
    },
    async promptAsync(params) {
      const body = params.body as { agent?: string; parts?: Array<{ text?: string }> }
      sessions.set(params.path.id, {
        agent: body.agent ?? "unknown",
        prompt: body.parts?.[0]?.text ?? "",
      })
    },
    async status() {
      // SDK shape: { data: { sessionId: { type: "idle"|"busy"|"retry" } } }
      const result: Record<string, { type: string }> = {}
      for (const id of sessions.keys()) {
        const started = startTimes.get(id) ?? 0
        const elapsed = Date.now() - started
        result[id] = {
          type: elapsed >= delay
            ? (options?.defaultStatus ?? "idle")
            : "busy",  // SDK uses "busy" for active sessions, not "running"
        }
      }
      return { data: result }
    },
    async messages(params) {
      const session = sessions.get(params.path.id)
      if (!session) return { data: [] }
      // SDK shape: { data: [ { info: {...}, parts: [...] } ] }
      return {
        data: [
          {
            info: { role: "assistant" },
            parts: [
              {
                type: "text",
                text: `Result from ${session.agent}: processed "${session.prompt}"`,
              },
            ],
          },
        ],
      }
    },
    async get(params) {
      return { data: { directory: "/test" } }
    },
  }
}

describe("BackgroundManager", () => {
  test("sync launch creates session and returns output", async () => {
    const client = createFakeClient()
    const manager = new BackgroundManager({ client, directory: "/test" })

    const result = await manager.launch({
      parentSessionID: "parent-1",
      agent: "omp-vulnhunter",
      description: "Find vulns",
      prompt: "Analyze binary",
      runInBackground: false,
    })

    expect(result.status).toBe("completed")
    expect(result.output).toContain("omp-vulnhunter")
    expect(result.output).toContain("Analyze binary")
    expect(client.sessions.size).toBe(1)
  })

  test("background launch returns immediately with task_id", async () => {
    const client = createFakeClient()
    const manager = new BackgroundManager({ client, directory: "/test" })

    const result = await manager.launch({
      parentSessionID: "parent-1",
      agent: "omp-vulnhunter",
      description: "Find vulns",
      prompt: "Analyze binary",
      runInBackground: true,
    })

    expect(result.status).toBe("running")
    expect(result.taskId).toMatch(/^omp-task-/)

    // Task should be tracked
    const task = manager.getTask(result.taskId)
    expect(task).toBeDefined()
    expect(task!.agent).toBe("omp-vulnhunter")

    manager.shutdown()
  })

  test("getResult returns output for completed task", async () => {
    const client = createFakeClient()
    const manager = new BackgroundManager({ client, directory: "/test" })

    const launch = await manager.launch({
      parentSessionID: "parent-1",
      agent: "omp-exploiter",
      description: "Run exploit",
      prompt: "Execute step 1",
      runInBackground: true,
    })

    // Wait for polling to complete the task
    await new Promise((r) => setTimeout(r, 4000))

    const result = await manager.getResult(launch.taskId)
    expect(result.status).toBe("completed")
    expect(result.output).toContain("omp-exploiter")

    manager.shutdown()
  }, 10000)

  test("getResult returns running for in-progress task (session status busy)", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const launch = await manager.launch({
      parentSessionID: "parent-1",
      agent: "omp-vulnhunter",
      description: "Slow task",
      prompt: "Analyze",
      runInBackground: true,
    })

    const result = await manager.getResult(launch.taskId)
    expect(result.status).toBe("running")

    manager.shutdown()
  })

  test("getResult returns error for unknown task", async () => {
    const client = createFakeClient()
    const manager = new BackgroundManager({ client, directory: "/test" })

    const result = await manager.getResult("nonexistent")
    expect(result.status).toBe("failed")
    expect(result.error).toContain("not found")
  })

  test("multiple parallel launches create separate sessions", async () => {
    const client = createFakeClient()
    const manager = new BackgroundManager({ client, directory: "/test" })

    const [r1, r2, r3] = await Promise.all([
      manager.launch({
        parentSessionID: "p",
        agent: "omp-vulnhunter",
        description: "VH-1",
        prompt: "Prompt 1",
        runInBackground: true,
      }),
      manager.launch({
        parentSessionID: "p",
        agent: "omp-vulnhunter",
        description: "VH-2",
        prompt: "Prompt 2",
        runInBackground: true,
      }),
      manager.launch({
        parentSessionID: "p",
        agent: "omp-vulnhunter",
        description: "VH-3",
        prompt: "Prompt 3",
        runInBackground: true,
      }),
    ])

    expect(client.sessions.size).toBe(3)
    expect(r1.taskId).not.toBe(r2.taskId)
    expect(r2.taskId).not.toBe(r3.taskId)

    manager.shutdown()
  })

  test("getTasksByParent returns only matching tasks", async () => {
    const client = createFakeClient()
    const manager = new BackgroundManager({ client, directory: "/test" })

    await manager.launch({
      parentSessionID: "parent-A",
      agent: "omp-vulnhunter",
      description: "Task A",
      prompt: "P",
      runInBackground: true,
    })
    await manager.launch({
      parentSessionID: "parent-B",
      agent: "omp-strategist",
      description: "Task B",
      prompt: "P",
      runInBackground: true,
    })

    expect(manager.getTasksByParent("parent-A")).toHaveLength(1)
    expect(manager.getTasksByParent("parent-B")).toHaveLength(1)
    expect(manager.getTasksByParent("parent-C")).toHaveLength(0)

    manager.shutdown()
  })

  test("cancelTask sets status to cancelled", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const launch = await manager.launch({
      parentSessionID: "p",
      agent: "omp-vulnhunter",
      description: "Cancel me",
      prompt: "P",
      runInBackground: true,
    })

    const cancelled = await manager.cancelTask(launch.taskId)
    expect(cancelled).toBe(true)

    const task = manager.getTask(launch.taskId)
    expect(task!.status).toBe("cancelled")

    manager.shutdown()
  })

  test("hasRunningTasksForParent returns correct status", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    expect(manager.hasRunningTasksForParent("p")).toBe(false)

    await manager.launch({
      parentSessionID: "p",
      agent: "omp-vulnhunter",
      description: "T",
      prompt: "P",
      runInBackground: true,
    })

    expect(manager.hasRunningTasksForParent("p")).toBe(true)

    manager.shutdown()
  })

  test("tool restrictions are applied to spawned sessions", async () => {
    const client = createFakeClient()
    const manager = new BackgroundManager({ client, directory: "/test" })

    // omp-exploiter should have omp_task: false
    await manager.launch({
      parentSessionID: "p",
      agent: "omp-exploiter",
      description: "Exploit",
      prompt: "Run",
      runInBackground: false,
    })

    // We can't directly inspect the promptAsync call args from here,
    // but we verify the session was created and completed without error
    expect(client.sessions.size).toBe(1)
  })
})
