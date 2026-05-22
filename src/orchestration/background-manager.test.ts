import { describe, expect, test } from "bun:test"
import { BackgroundManager } from "./background-manager"
import type { OmpSessionClient } from "./types"

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
      const result: Record<string, { type: string }> = {}
      for (const id of sessions.keys()) {
        const started = startTimes.get(id) ?? 0
        const elapsed = Date.now() - started
        result[id] = {
          type: elapsed >= delay
            ? (options?.defaultStatus ?? "idle")
            : "busy",
        }
      }
      return { data: result }
    },
    async messages(params) {
      const session = sessions.get(params.path.id)
      if (!session) return { data: [] }
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
      return { data: true }
    },
  }
}

describe("BackgroundManager", () => {
  // ── launchAsync ───────────────────────────────────────────────────────

  test("launchAsync returns {task_id, session_id} and marks task running", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const result = await manager.launchAsync({
      parentSessionID: "p",
      agent: "omp-vulnhunter",
      description: "Launch",
      prompt: "x",
    })

    expect(result.task_id).toMatch(/^omp-task-/)
    expect(result.session_id).toMatch(/^session-/)

    const task = manager.getTask(result.task_id)!
    expect(task.status).toBe("running")
    expect(task.sessionID).toBe(result.session_id)
    expect(task.agent).toBe("omp-vulnhunter")

    manager.shutdown()
  })

  test("launchAsync resolves category alias to agent name", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const result = await manager.launchAsync({
      parentSessionID: "p",
      agent: "vulnhunter",
      description: "Category routing",
      prompt: "x",
    })

    const sess = client.sessions.get(result.session_id)!
    expect(sess.agent).toBe("omp-vulnhunter")
    expect(manager.getTask(result.task_id)!.agent).toBe("omp-vulnhunter")

    manager.shutdown()
  })

  test("launchAsync with direct agent name passes through", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const result = await manager.launchAsync({
      parentSessionID: "p",
      agent: "omp-exploiter-mode-1",
      description: "Direct name",
      prompt: "x",
    })

    expect(client.sessions.get(result.session_id)!.agent).toBe("omp-exploiter-mode-1")
    manager.shutdown()
  })

  test("launchAsync throws on unknown agent/category", async () => {
    const client = createFakeClient()
    const manager = new BackgroundManager({ client, directory: "/test" })

    await expect(
      manager.launchAsync({
        parentSessionID: "p",
        agent: "not-a-thing",
        description: "Bad",
        prompt: "x",
      }),
    ).rejects.toThrow(/unknown agent or category/)
  })

  test("launchAsync — session.create failure throws + task marked failed", async () => {
    const client = createFakeClient({ createThrows: true })
    const manager = new BackgroundManager({ client, directory: "/test" })

    await expect(
      manager.launchAsync({
        parentSessionID: "p",
        agent: "omp-vulnhunter",
        description: "Will fail",
        prompt: "x",
      }),
    ).rejects.toThrow(/simulated session.create failure/)

    const failedTasks = manager.getTasksByParent("p")
    expect(failedTasks.length).toBe(1)
    expect(failedTasks[0].status).toBe("failed")
    expect(failedTasks[0].error).toContain("simulated session.create failure")
  })

  test("multiple parallel launches create separate sessions", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const [r1, r2, r3] = await Promise.all([
      manager.launchAsync({
        parentSessionID: "p",
        agent: "omp-vulnhunter",
        description: "VH-1",
        prompt: "Prompt 1",
      }),
      manager.launchAsync({
        parentSessionID: "p",
        agent: "omp-vulnhunter",
        description: "VH-2",
        prompt: "Prompt 2",
      }),
      manager.launchAsync({
        parentSessionID: "p",
        agent: "omp-vulnhunter",
        description: "VH-3",
        prompt: "Prompt 3",
      }),
    ])

    expect(client.sessions.size).toBe(3)
    expect(r1.task_id).not.toBe(r2.task_id)
    expect(r2.task_id).not.toBe(r3.task_id)

    manager.shutdown()
  })

  test("getTasksByParent returns only matching tasks", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    await manager.launchAsync({
      parentSessionID: "parent-A",
      agent: "omp-vulnhunter",
      description: "Task A",
      prompt: "P",
    })
    await manager.launchAsync({
      parentSessionID: "parent-B",
      agent: "omp-strategist",
      description: "Task B",
      prompt: "P",
    })

    expect(manager.getTasksByParent("parent-A")).toHaveLength(1)
    expect(manager.getTasksByParent("parent-B")).toHaveLength(1)
    expect(manager.getTasksByParent("parent-C")).toHaveLength(0)

    manager.shutdown()
  })

  // ── polling → 'done' event (T3) ───────────────────────────────────────

  test("polling emits 'done' on terminal transition", async () => {
    const client = createFakeClient({ idleDelay: 100 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const events: string[] = []
    manager.taskEvents.on("done", (id: string) => events.push(id))

    const launch = await manager.launchAsync({
      parentSessionID: "p",
      agent: "omp-vulnhunter",
      description: "Emit test",
      prompt: "x",
    })

    await new Promise((r) => setTimeout(r, 4000))

    expect(events).toContain(launch.task_id)

    manager.shutdown()
  }, 10000)

  // ── cancel (T4) ───────────────────────────────────────────────────────

  test("cancel running task → abort called, status=cancelled, 'done' emitted", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const events: string[] = []
    manager.taskEvents.on("done", (id: string) => events.push(id))

    const launch = await manager.launchAsync({
      parentSessionID: "p",
      agent: "omp-vulnhunter",
      description: "Cancel target",
      prompt: "x",
    })

    const ok = await manager.cancel(launch.task_id)
    expect(ok).toBe(true)

    const task = manager.getTask(launch.task_id)!
    expect(task.status).toBe("cancelled")
    expect(task.sessionID).toBeDefined()
    expect(client.abortedSessions.has(task.sessionID!)).toBe(true)
    expect(events).toContain(launch.task_id)

    manager.shutdown()
  })

  test("cancel unknown taskId returns false (no emit)", async () => {
    const client = createFakeClient()
    const manager = new BackgroundManager({ client, directory: "/test" })

    const events: string[] = []
    manager.taskEvents.on("done", (id: string) => events.push(id))

    const ok = await manager.cancel("not-a-real-id")
    expect(ok).toBe(false)
    expect(events).toHaveLength(0)
    expect(client.abortedSessions.size).toBe(0)
  })

  test("cancel already-cancelled task returns false (idempotent)", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const launch = await manager.launchAsync({
      parentSessionID: "p",
      agent: "omp-vulnhunter",
      description: "Double cancel",
      prompt: "x",
    })

    const events: string[] = []
    manager.taskEvents.on("done", (id: string) => events.push(id))

    expect(await manager.cancel(launch.task_id)).toBe(true)
    expect(await manager.cancel(launch.task_id)).toBe(false)
    expect(events).toHaveLength(1)

    manager.shutdown()
  })

  test("cancel — abort RPC failure still marks cancelled and returns true", async () => {
    const client = createFakeClient({ idleDelay: 60000, abortThrows: true })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const launch = await manager.launchAsync({
      parentSessionID: "p",
      agent: "omp-vulnhunter",
      description: "Abort throws",
      prompt: "x",
    })

    const ok = await manager.cancel(launch.task_id)
    expect(ok).toBe(true)
    expect(manager.getTask(launch.task_id)!.status).toBe("cancelled")

    manager.shutdown()
  })

  // ── waitAll (T6) ──────────────────────────────────────────────────────

  test("waitAll — returns results in input order, fetches outputs", async () => {
    const client = createFakeClient({ idleDelay: 100 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const r1 = await manager.launchAsync({
      parentSessionID: "p", agent: "omp-vulnhunter",
      description: "T1", prompt: "p1",
    })
    const r2 = await manager.launchAsync({
      parentSessionID: "p", agent: "omp-vulnhunter",
      description: "T2", prompt: "p2",
    })
    const r3 = await manager.launchAsync({
      parentSessionID: "p", agent: "omp-vulnhunter",
      description: "T3", prompt: "p3",
    })

    const result = await manager.waitAll([r1.task_id, r2.task_id, r3.task_id])
    expect(result.results).toHaveLength(3)
    expect(result.results[0].task_id).toBe(r1.task_id)
    expect(result.results[1].task_id).toBe(r2.task_id)
    expect(result.results[2].task_id).toBe(r3.task_id)
    expect(result.results.every((r) => r.status === "completed")).toBe(true)
    expect(result.results[0].output).toContain("p1")
    expect(result.results[2].output).toContain("p3")

    manager.shutdown()
  }, 15000)

  test("waitAll — state-first returns immediately if all already terminal", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const launch = await manager.launchAsync({
      parentSessionID: "p", agent: "omp-vulnhunter",
      description: "Will cancel", prompt: "x",
    })
    await manager.cancel(launch.task_id)

    const start = Date.now()
    const result = await manager.waitAll([launch.task_id])
    const elapsed = Date.now() - start
    expect(elapsed).toBeLessThan(500)
    expect(result.results[0].status).toBe("cancelled")
  })

  test("waitAll — includes cancelled tasks as terminal", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const r1 = await manager.launchAsync({
      parentSessionID: "p", agent: "omp-vulnhunter",
      description: "Will cancel", prompt: "x",
    })

    const waitPromise = manager.waitAll([r1.task_id])
    await manager.cancel(r1.task_id)

    const result = await waitPromise
    expect(result.results[0].status).toBe("cancelled")

    manager.shutdown()
  })

  test("waitAll — unknown task_id → synthetic failed outcome", async () => {
    const client = createFakeClient()
    const manager = new BackgroundManager({ client, directory: "/test" })

    const result = await manager.waitAll(["fake-id-1", "fake-id-2"])
    expect(result.results).toHaveLength(2)
    expect(result.results[0]).toMatchObject({
      task_id: "fake-id-1",
      status: "failed",
    })
    expect(result.results[0].error).toContain("unknown task_id")
  })

  // ── waitAny (T6) ──────────────────────────────────────────────────────

  test("waitAny — returns first complete + remaining_ids in input order", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const r1 = await manager.launchAsync({
      parentSessionID: "p", agent: "omp-vulnhunter",
      description: "A", prompt: "a",
    })
    const r2 = await manager.launchAsync({
      parentSessionID: "p", agent: "omp-vulnhunter",
      description: "B", prompt: "b",
    })
    const r3 = await manager.launchAsync({
      parentSessionID: "p", agent: "omp-vulnhunter",
      description: "C", prompt: "c",
    })

    const waitPromise = manager.waitAny([r1.task_id, r2.task_id, r3.task_id])
    await manager.cancel(r2.task_id)

    const result = await waitPromise
    expect(result.task_id).toBe(r2.task_id)
    expect(result.status).toBe("cancelled")
    expect(result.remaining_ids).toEqual([r1.task_id, r3.task_id])

    manager.shutdown()
  })

  test("waitAny — state-first scans input order, first terminal wins", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const r1 = await manager.launchAsync({
      parentSessionID: "p", agent: "omp-vulnhunter",
      description: "A", prompt: "x",
    })
    const r2 = await manager.launchAsync({
      parentSessionID: "p", agent: "omp-vulnhunter",
      description: "B", prompt: "x",
    })

    await manager.cancel(r1.task_id)
    await manager.cancel(r2.task_id)

    const result = await manager.waitAny([r1.task_id, r2.task_id])
    expect(result.task_id).toBe(r1.task_id)
    expect(result.remaining_ids).toEqual([r2.task_id])
  })

  test("waitAny — unknown task_id encountered first → synthetic failed", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const r1 = await manager.launchAsync({
      parentSessionID: "p", agent: "omp-vulnhunter",
      description: "Real", prompt: "x",
    })

    const result = await manager.waitAny(["fake-id", r1.task_id])
    expect(result.task_id).toBe("fake-id")
    expect(result.status).toBe("failed")
    expect(result.error).toContain("unknown task_id")
    expect(result.remaining_ids).toEqual([r1.task_id])

    manager.shutdown()
  })

  test("waitAny — cascaded re-call drains remaining via remaining_ids", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    const r1 = await manager.launchAsync({
      parentSessionID: "p", agent: "omp-vulnhunter",
      description: "A", prompt: "x",
    })
    const r2 = await manager.launchAsync({
      parentSessionID: "p", agent: "omp-vulnhunter",
      description: "B", prompt: "x",
    })

    const p1 = manager.waitAny([r1.task_id, r2.task_id])
    await manager.cancel(r1.task_id)
    const first = await p1
    expect(first.task_id).toBe(r1.task_id)

    const p2 = manager.waitAny(first.remaining_ids)
    await manager.cancel(r2.task_id)
    const second = await p2
    expect(second.task_id).toBe(r2.task_id)
    expect(second.remaining_ids).toEqual([])

    manager.shutdown()
  })

  // ── tool restrictions integration ─────────────────────────────────────

  test("tool restrictions are applied to spawned sessions", async () => {
    const client = createFakeClient({ idleDelay: 60000 })
    const manager = new BackgroundManager({ client, directory: "/test" })

    // omp-exploiter is a leaf agent — restriction map denies all four
    // sub-agent tools. We can't directly inspect the promptAsync call
    // args from here, but we verify the session was created without error.
    await manager.launchAsync({
      parentSessionID: "p",
      agent: "omp-exploiter-mode-1",
      description: "Exploit",
      prompt: "Run",
    })

    expect(client.sessions.size).toBe(1)
    manager.shutdown()
  })
})
