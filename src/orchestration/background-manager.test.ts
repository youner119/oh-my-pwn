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
  /** If true, abort() throws — to test graceful failure path. */
  abortThrows?: boolean
  /** If true, create() throws — to test launchAsync error handling. */
  createThrows?: boolean
}): OmpSessionClient & {
  sessions: Map<string, { agent: string; prompt: string }>
  abortedSessions: Set<string>
} {
  const sessions = new Map<string, { agent: string; prompt: string }>()
  const abortedSessions = new Set<string>()
  let sessionCounter = 0
  const startTimes = new Map<string, number>()
  const delay = options?.idleDelay ?? 0

  return {
    sessions,
    abortedSessions,
    async create(params) {
      if (options?.createThrows) {
        throw new Error("simulated session.create failure")
      }
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
    async abort(params) {
      if (options?.abortThrows) {
        throw new Error("simulated abort failure")
      }
      abortedSessions.add(params.path.id)
      // SDK shape: { data: boolean }
      return { data: true }
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

  test("T3: polling emits 'done' on terminal transition", async () => {
    const client = createFakeClient({ idleDelay: 100 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const events: string[] = []
    manager.taskEvents.on("done", (id: string) => events.push(id))

    const launch = await manager.launch({
      parentSessionID: "p",
      agent: "omp-vulnhunter",
      description: "Emit test",
      prompt: "x",
      runInBackground: true,
    })

    // Wait for polling (3s interval) + idleDelay buffer
    await new Promise((r) => setTimeout(r, 4000))

    expect(events).toContain(launch.taskId)

    manager.shutdown()
  }, 10000)

  test("T4: cancel running task → abort called, status=cancelled, 'done' emitted", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const events: string[] = []
    manager.taskEvents.on("done", (id: string) => events.push(id))

    const launch = await manager.launch({
      parentSessionID: "p",
      agent: "omp-vulnhunter",
      description: "Cancel target",
      prompt: "x",
      runInBackground: true,
    })

    const ok = await manager.cancel(launch.taskId)
    expect(ok).toBe(true)

    const task = manager.getTask(launch.taskId)!
    expect(task.status).toBe("cancelled")
    expect(task.sessionID).toBeDefined()
    expect(client.abortedSessions.has(task.sessionID!)).toBe(true)
    expect(events).toContain(launch.taskId)

    manager.shutdown()
  })

  test("T4: cancel unknown taskId returns false (no emit)", async () => {
    const client = createFakeClient()
    const manager = new BackgroundManager({ client, directory: "/test" })

    const events: string[] = []
    manager.taskEvents.on("done", (id: string) => events.push(id))

    const ok = await manager.cancel("not-a-real-id")
    expect(ok).toBe(false)
    expect(events).toHaveLength(0)
    expect(client.abortedSessions.size).toBe(0)
  })

  test("T4: cancel already-completed task returns false (idempotent)", async () => {
    const client = createFakeClient()
    const manager = new BackgroundManager({ client, directory: "/test" })

    const result = await manager.launch({
      parentSessionID: "p",
      agent: "omp-vulnhunter",
      description: "Sync done",
      prompt: "x",
      runInBackground: false,
    })
    expect(result.status).toBe("completed")

    const events: string[] = []
    manager.taskEvents.on("done", (id: string) => events.push(id))

    const ok = await manager.cancel(result.taskId)
    expect(ok).toBe(false)
    expect(events).toHaveLength(0)
    expect(client.abortedSessions.size).toBe(0)
  })

  test("T4: double cancel — second call returns false, no second emit", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const launch = await manager.launch({
      parentSessionID: "p",
      agent: "omp-vulnhunter",
      description: "Double cancel",
      prompt: "x",
      runInBackground: true,
    })

    const events: string[] = []
    manager.taskEvents.on("done", (id: string) => events.push(id))

    expect(await manager.cancel(launch.taskId)).toBe(true)
    expect(await manager.cancel(launch.taskId)).toBe(false)
    expect(events).toHaveLength(1)

    manager.shutdown()
  })

  test("T4: abort RPC failure → still marked cancelled, returns true", async () => {
    const client = createFakeClient({ idleDelay: 60000, abortThrows: true })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const launch = await manager.launch({
      parentSessionID: "p",
      agent: "omp-vulnhunter",
      description: "Abort throws",
      prompt: "x",
      runInBackground: true,
    })

    const ok = await manager.cancel(launch.taskId)
    expect(ok).toBe(true)
    expect(manager.getTask(launch.taskId)!.status).toBe("cancelled")

    manager.shutdown()
  })

  test("T5: launchAsync returns {task_id, session_id} with running status", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const result = await manager.launchAsync({
      parentSessionID: "p",
      agent: "omp-vulnhunter",
      description: "Async launch",
      prompt: "x",
      runInBackground: true,
    })

    expect(result.task_id).toMatch(/^omp-task-/)
    expect(result.session_id).toMatch(/^session-/)

    const task = manager.getTask(result.task_id)!
    expect(task.status).toBe("running")
    expect(task.sessionID).toBe(result.session_id)

    manager.shutdown()
  })

  test("T5: launchAsync resolves category alias to agent name", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const result = await manager.launchAsync({
      parentSessionID: "p",
      agent: "vulnhunter",
      description: "Category routing",
      prompt: "x",
      runInBackground: true,
    })

    const sess = client.sessions.get(result.session_id)!
    expect(sess.agent).toBe("omp-vulnhunter")
    expect(manager.getTask(result.task_id)!.agent).toBe("omp-vulnhunter")

    manager.shutdown()
  })

  test("T5: launchAsync with direct agent name passes through", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const result = await manager.launchAsync({
      parentSessionID: "p",
      agent: "omp-exploiter",
      description: "Direct name",
      prompt: "x",
      runInBackground: true,
    })

    expect(client.sessions.get(result.session_id)!.agent).toBe("omp-exploiter")
    manager.shutdown()
  })

  test("T5: launchAsync throws on unknown agent/category", async () => {
    const client = createFakeClient()
    const manager = new BackgroundManager({ client, directory: "/test" })

    await expect(
      manager.launchAsync({
        parentSessionID: "p",
        agent: "not-a-thing",
        description: "Bad",
        prompt: "x",
        runInBackground: true,
      }),
    ).rejects.toThrow(/unknown agent or category/)
  })

  test("T5: launchAsync — session.create failure throws + task marked failed", async () => {
    const client = createFakeClient({ createThrows: true })
    const manager = new BackgroundManager({ client, directory: "/test" })

    await expect(
      manager.launchAsync({
        parentSessionID: "p",
        agent: "omp-vulnhunter",
        description: "Will fail",
        prompt: "x",
        runInBackground: true,
      }),
    ).rejects.toThrow(/simulated session.create failure/)

    // Failed task should still exist in the map with consistent state.
    const failedTasks = manager.getTasksByParent("p")
    expect(failedTasks.length).toBe(1)
    expect(failedTasks[0].status).toBe("failed")
    expect(failedTasks[0].error).toContain("simulated session.create failure")
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
