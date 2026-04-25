/**
 * BackgroundManager — manages parallel sub-agent sessions.
 *
 * Simplified port of OmO's background-agent/manager.ts:
 * - tmux pane spawning for sub-agent visibility
 * - No skill injection, no session cursor dedup
 * - No category resolver (direct agent name only)
 * - Supports both sync (blocking) and background (fire-and-forget) modes
 * - DI-friendly via OmpSessionClient interface
 */

import type {
  BackgroundTask,
  LaunchInput,
  OmpSessionClient,
  TaskResult,
  TextPart,
} from "./types"
import { ConcurrencyManager } from "./concurrency"
import { getAgentToolRestrictions } from "./agent-tool-restrictions"
import { isInsideTmux, spawnSubagentPane, closeTmuxPane, resetPaneTracking } from "./tmux"
import { appendFileSync, mkdirSync } from "node:fs"
import { join } from "node:path"

let logPath: string | undefined

function ompLog(msg: string): void {
  if (!logPath) return
  try {
    const timestamp = new Date().toISOString()
    appendFileSync(logPath, `[${timestamp}] ${msg}\n`)
  } catch {
    // logging failure is non-fatal
  }
}

const POLLING_INTERVAL_MS = 3000

/**
 * opencode SDK SessionStatus.type values:
 * - "idle"  → session finished (sub-agent done)
 * - "busy"  → session actively running
 * - "retry" → model error, retrying (still active)
 *
 * We treat "busy" and "retry" as active (keep waiting).
 * "idle" or absent means done.
 */
const IDLE_STATUSES = new Set(["idle"])

let taskCounter = 0
function generateTaskId(): string {
  taskCounter += 1
  return `omp-task-${Date.now()}-${taskCounter}`
}

function isIdleStatus(status: string): boolean {
  return IDLE_STATUSES.has(status)
}

function extractAssistantText(
  messages: Array<{
    info?: { role: string }
    parts?: Array<{ type: string; text?: string }>
  }>,
): string {
  const texts: string[] = []
  for (const msg of messages) {
    if (msg.info?.role !== "assistant") continue
    for (const part of msg.parts ?? []) {
      if (part.type === "text" && part.text) {
        texts.push(part.text)
      }
    }
  }
  return texts.join("\n\n")
}

/**
 * Unwrap SDK response — opencode SDK wraps responses in { data, request, response }.
 * This helper extracts .data if present, or returns the value as-is.
 */
function unwrapData<T>(result: unknown): T {
  if (result && typeof result === "object" && "data" in result) {
    return (result as { data: T }).data
  }
  return result as T
}

export interface BackgroundManagerOptions {
  client: OmpSessionClient
  directory: string
  /** opencode server URL for tmux attach. e.g., "http://localhost:4096" */
  serverUrl?: string
  concurrency?: { defaultLimit?: number; modelLimits?: Record<string, number> }
}

export class BackgroundManager {
  private readonly client: OmpSessionClient
  private readonly directory: string
  private readonly serverUrl?: string
  private readonly tasks = new Map<string, BackgroundTask>()
  private readonly paneIds = new Map<string, string>() // taskId → tmux paneId
  private readonly sessionPaneIds = new Map<string, string>() // sessionID → tmux paneId
  private readonly concurrency: ConcurrencyManager
  private pollingInterval?: ReturnType<typeof setInterval>
  private pollingInFlight = false

  constructor(options: BackgroundManagerOptions) {
    this.client = options.client
    this.directory = options.directory
    this.serverUrl = options.serverUrl
    this.concurrency = new ConcurrencyManager(options.concurrency)

    // Initialize log file at .omp/logs/orchestration.log
    try {
      const logsDir = join(this.directory, ".omp", "logs")
      mkdirSync(logsDir, { recursive: true })
      logPath = join(logsDir, "orchestration.log")
      ompLog("BackgroundManager initialized")
    } catch {
      // If directory doesn't exist yet (no challenge loaded), skip logging
    }
  }

  /**
   * Launch a sub-agent task.
   *
   * - `runInBackground=true`: returns immediately with taskId. Poll via getResult().
   * - `runInBackground=false`: blocks until sub-session completes, returns result.
   */
  async launch(input: LaunchInput): Promise<TaskResult> {
    const task = this.createTask(input)
    const concurrencyKey = task.concurrencyKey

    // Acquire concurrency slot
    await this.concurrency.acquire(concurrencyKey)

    try {
      await this.startSession(task, input)
    } catch (err) {
      this.concurrency.release(concurrencyKey)
      task.status = "failed"
      task.error = String(err)
      return { taskId: task.id, status: "failed", error: task.error }
    }

    if (input.runInBackground) {
      this.ensurePolling()
      return { taskId: task.id, status: "running" }
    }

    // Sync mode: poll until completion
    return this.waitForCompletion(task)
  }

  /** Get a task by ID. */
  getTask(id: string): BackgroundTask | undefined {
    return this.tasks.get(id)
  }

  /** Get all tasks spawned by a parent session. */
  getTasksByParent(parentSessionID: string): BackgroundTask[] {
    const result: BackgroundTask[] = []
    for (const task of this.tasks.values()) {
      if (task.parentSessionID === parentSessionID) result.push(task)
    }
    return result
  }

  /** Get output from a completed/failed task. */
  async getResult(taskId: string): Promise<TaskResult> {
    const task = this.tasks.get(taskId)
    if (!task) {
      return { taskId, status: "failed", error: `Task ${taskId} not found` }
    }

    if (task.status === "running" || task.status === "queued") {
      return { taskId, status: task.status }
    }

    if (task.status === "failed" || task.status === "cancelled") {
      return { taskId, status: task.status, error: task.error }
    }

    // Completed — fetch output
    if (!task.sessionID) {
      return { taskId, status: "completed", output: "" }
    }

    try {
      const output = await this.fetchSessionOutput(task.sessionID)
      return { taskId, status: "completed", output }
    } catch (err) {
      return {
        taskId,
        status: "completed",
        output: `(output fetch failed: ${String(err)})`,
      }
    }
  }

  /** Check if any background tasks from a parent session are still running. */
  hasRunningTasksForParent(parentSessionID: string): boolean {
    for (const task of this.tasks.values()) {
      if (
        task.parentSessionID === parentSessionID &&
        (task.status === "running" || task.status === "queued")
      ) {
        return true
      }
    }
    return false
  }

  /**
   * Launch multiple tasks and wait for ALL to complete (wait-all).
   * Used for VH ensemble and Reverser — we need every result.
   */
  async launchAll(inputs: LaunchInput[]): Promise<TaskResult[]> {
    ompLog(`launchAll: starting ${inputs.length} tasks (wait-all)`)

    const promises = inputs.map((input) =>
      this.launchAndWait(input),
    )
    const results = await Promise.all(promises)

    ompLog(`launchAll: all ${inputs.length} tasks completed`)
    return results
  }

  /**
   * Launch tasks with a concurrency limit, early-exit on flag.
   * Used for SA+Exploiter — max N running at once, stop if flag found.
   *
   * @param inputs - all tasks to run
   * @param maxConcurrency - max simultaneous tasks (default 3)
   * @param isFlag - callback to check if a result contains a flag
   * @returns collected results (may be partial if early-exit triggered)
   */
  async launchPool(
    inputs: LaunchInput[],
    maxConcurrency: number,
    isFlag: (result: TaskResult) => boolean,
  ): Promise<{ results: TaskResult[]; flagFound: boolean }> {
    ompLog(`launchPool: ${inputs.length} tasks, max concurrency ${maxConcurrency}`)

    const results: TaskResult[] = []
    const queue = [...inputs]
    const executing = new Map<Promise<void>, string>() // promise → taskId
    let flagFound = false

    const launchNext = async (): Promise<void> => {
      if (queue.length === 0 || flagFound) return

      const input = queue.shift()!
      const resultPromise = this.launchAndWait(input).then((result) => {
        results.push(result)
        executing.delete(p)

        if (isFlag(result)) {
          flagFound = true
          ompLog(`launchPool: FLAG FOUND in task ${result.taskId} — stopping`)
        }
      })
      const p = resultPromise
      executing.set(p, input.description)
    }

    // Fill initial slots
    while (executing.size < maxConcurrency && queue.length > 0) {
      await launchNext()
    }

    // As each finishes, launch next from queue
    while (executing.size > 0) {
      await Promise.race(executing.keys())

      // Fill freed slots
      while (executing.size < maxConcurrency && queue.length > 0 && !flagFound) {
        await launchNext()
      }
    }

    ompLog(`launchPool: done. ${results.length} results, flagFound=${flagFound}`)
    return { results, flagFound }
  }

  /**
   * Internal: launch a single task and wait for completion.
   * Reuses startSession + waitForCompletion. Always blocking.
   */
  private async launchAndWait(input: LaunchInput): Promise<TaskResult> {
    const task = this.createTask(input)
    await this.concurrency.acquire(task.concurrencyKey)

    try {
      await this.startSession(task, { ...input, runInBackground: false })
    } catch (err) {
      this.concurrency.release(task.concurrencyKey)
      task.status = "failed"
      task.error = String(err)
      return { taskId: task.id, status: "failed", error: task.error }
    }

    return this.waitForCompletion(task)
  }

  /** Cancel a running task. */
  async cancelTask(taskId: string): Promise<boolean> {
    const task = this.tasks.get(taskId)
    if (!task || task.status !== "running") return false
    task.status = "cancelled"
    task.completedAt = new Date()
    this.concurrency.release(task.concurrencyKey)
    return true
  }

  /** Shut down: cancel all waiters, stop polling, close panes. */
  shutdown(): void {
    this.stopPolling()
    this.concurrency.clear()
    // Close all tmux panes and reset tracking
    for (const [, paneId] of this.paneIds) {
      void closeTmuxPane(paneId)
    }
    this.paneIds.clear()
    this.sessionPaneIds.clear()
    resetPaneTracking()
  }

  /** Close the tmux pane for a completed task. */
  private closePaneForTask(taskId: string): void {
    const paneId = this.paneIds.get(taskId)
    if (paneId) {
      ompLog(`Task ${taskId}: closing tmux pane ${paneId}`)
      void closeTmuxPane(paneId)
      this.paneIds.delete(taskId)
    }
  }

  /* ── Internal ───────────────────────────────────────────────────────── */

  private createTask(input: LaunchInput): BackgroundTask {
    const id = generateTaskId()
    const concurrencyKey = input.model
      ? `${input.model.providerID}/${input.model.modelID}`
      : input.agent
    const task: BackgroundTask = {
      id,
      parentSessionID: input.parentSessionID,
      agent: input.agent,
      description: input.description,
      prompt: input.prompt,
      status: "queued",
      createdAt: new Date(),
      concurrencyKey,
    }
    this.tasks.set(id, task)
    return task
  }

  private async startSession(
    task: BackgroundTask,
    input: LaunchInput,
  ): Promise<void> {
    // Resolve parent directory
    let parentDirectory = this.directory
    try {
      const rawSession = await this.client.get({
        path: { id: input.parentSessionID },
        query: { directory: this.directory },
      })
      const parentSession = unwrapData<{ directory?: string }>(rawSession)
      parentDirectory = parentSession?.directory ?? this.directory
    } catch {
      // Fall back to default directory
    }

    // Create child session.
    // Sub-agents must be fully autonomous — no user interaction possible.
    // Auto-allow all tool permissions so they never block on approval prompts.
    // Auto-deny "question" so they don't try to ask the user.
    const rawCreateResult = await this.client.create({
      body: {
        parentID: input.parentSessionID,
        title: `${input.description} (@${input.agent})`,
        permission: [
          { permission: "read", action: "allow", pattern: "*" },
          { permission: "write", action: "allow", pattern: "*" },
          { permission: "bash", action: "allow", pattern: "*" },
          { permission: "mcp", action: "allow", pattern: "*" },
          { permission: "external_directory", action: "allow", pattern: "*" },
          { permission: "question", action: "deny", pattern: "*" },
        ],
      } as Record<string, unknown>,
      query: { directory: parentDirectory },
    })
    const createData = unwrapData<{ id: string }>(rawCreateResult)
    const sessionID = createData.id

    ompLog(
      `session.create raw keys: ${Object.keys(rawCreateResult as object).join(", ")} | ` +
      `unwrapped: ${JSON.stringify(createData).slice(0, 200)} | sessionID: ${sessionID}`,
    )

    if (!sessionID) {
      throw new Error(
        `session.create returned no ID. Raw: ${JSON.stringify(rawCreateResult).slice(0, 300)}`,
      )
    }

    task.sessionID = sessionID
    task.status = "running"
    task.startedAt = new Date()

    // Build tool restrictions
    const tools: Record<string, boolean> = {
      ...getAgentToolRestrictions(input.agent),
      ...(input.tools ?? {}),
    }

    // Fire prompt (must happen BEFORE tmux attach — pane needs session activity)
    const parts: TextPart[] = [{ type: "text", text: input.prompt }]
    await this.client.promptAsync({
      path: { id: sessionID },
      body: {
        agent: input.agent,
        ...(input.model ? { model: input.model } : {}),
        tools,
        parts,
      },
    })

    ompLog(`Task ${task.id}: session ${sessionID} created for @${input.agent} (serverUrl: ${this.serverUrl ?? "none"})`)

    // Spawn tmux pane so the user can watch the sub-agent work.
    // If the parent session has a pane (e.g., SA), split it to place
    // this agent (e.g., Exploiter) to its right.
    if (this.serverUrl && isInsideTmux()) {
      const parentPaneId = this.sessionPaneIds.get(input.parentSessionID)
      const paneId = await spawnSubagentPane({
        serverUrl: this.serverUrl,
        sessionId: sessionID,
        title: input.description,
        parentPaneId,
      })
      if (paneId) {
        this.paneIds.set(task.id, paneId)
        this.sessionPaneIds.set(sessionID, paneId)
        ompLog(`Task ${task.id}: tmux pane ${paneId} opened${parentPaneId ? ` (child of ${parentPaneId})` : ""}`)
      }
    }
  }

  private async waitForCompletion(task: BackgroundTask): Promise<TaskResult> {
    // Poll until not active
    while (task.status === "running") {
      await sleep(POLLING_INTERVAL_MS)
      if (!task.sessionID) break
      await this.checkTaskStatus(task)
    }

    this.concurrency.release(task.concurrencyKey)

    if (task.status === "failed") {
      return { taskId: task.id, status: "failed", error: task.error }
    }

    const output = task.sessionID
      ? await this.fetchSessionOutput(task.sessionID)
      : ""
    return { taskId: task.id, status: "completed", output }
  }

  private ensurePolling(): void {
    if (this.pollingInterval) return
    this.pollingInterval = setInterval(() => {
      void this.pollRunningTasks()
    }, POLLING_INTERVAL_MS)
    // Don't keep the process alive just for polling
    if (this.pollingInterval.unref) this.pollingInterval.unref()
  }

  private stopPolling(): void {
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval)
      this.pollingInterval = undefined
    }
  }

  private async pollRunningTasks(): Promise<void> {
    if (this.pollingInFlight) return
    this.pollingInFlight = true

    try {
      const rawStatuses = await this.client.status()
      const statuses = unwrapData<Record<string, { type: string }>>(rawStatuses)

      for (const task of this.tasks.values()) {
        if (task.status !== "running" || !task.sessionID) continue
        const sessionStatus = statuses[task.sessionID]

        if (!sessionStatus) {
          // Session disappeared from status map.
          // If task has been running >10s, treat as completed (opencode cleaned up).
          if (task.startedAt && Date.now() - task.startedAt.getTime() > 10000) {
            ompLog(`Task ${task.id}: session disappeared → completed (poll)`)
            task.status = "completed"
            task.completedAt = new Date()
            this.concurrency.release(task.concurrencyKey)
            this.closePaneForTask(task.id)
          }
          continue
        }

        // Session is idle → sub-agent finished. Mark completed.
        // Any other status (busy, retry) → still running, keep waiting.
        if (!isIdleStatus(sessionStatus.type)) continue

        ompLog(`Task ${task.id}: session idle → completed (poll)`)
        task.status = "completed"
        task.completedAt = new Date()
        this.concurrency.release(task.concurrencyKey)
        this.closePaneForTask(task.id)
      }

      // Stop polling if no running tasks remain
      let hasRunning = false
      for (const task of this.tasks.values()) {
        if (task.status === "running") {
          hasRunning = true
          break
        }
      }
      if (!hasRunning) this.stopPolling()
    } catch {
      // Polling failure is non-fatal; retry next interval
    } finally {
      this.pollingInFlight = false
    }
  }

  private async checkTaskStatus(task: BackgroundTask): Promise<void> {
    if (!task.sessionID) return

    try {
      const rawStatuses = await this.client.status()
      ompLog(`status() raw keys: ${Object.keys(rawStatuses as object).join(", ")}`)
      const statuses = unwrapData<Record<string, { type: string }>>(rawStatuses)
      ompLog(`status() unwrapped keys: ${Object.keys(statuses ?? {}).join(", ")}`)
      const sessionStatus = statuses[task.sessionID]

      // Session not in status map has two meanings:
      // 1. Just created, not registered yet → keep waiting (task just started)
      // 2. Already completed and removed from status map → completed
      // Distinguish by checking if we've EVER seen it as busy.
      if (!sessionStatus) {
        if (task.startedAt && Date.now() - task.startedAt.getTime() > 10000) {
          // Task has been running for >10s but session disappeared from status map
          // → session completed and was cleaned up by opencode
          ompLog(`Task ${task.id}: session ${task.sessionID} disappeared from status map after running → completed`)
          task.status = "completed"
          task.completedAt = new Date()
          this.concurrency.release(task.concurrencyKey)
          this.closePaneForTask(task.id)
        } else {
          ompLog(`Task ${task.id}: session ${task.sessionID} not in status map yet (startup grace period)`)
        }
        return
      }

      // Session still active (busy, retry) — keep waiting
      if (!isIdleStatus(sessionStatus.type)) {
        ompLog(`Task ${task.id}: session status = ${sessionStatus.type} (waiting)`)
        return
      }

      // Session is idle — sub-agent finished
      ompLog(`Task ${task.id}: session idle → completed`)
      task.status = "completed"
      task.completedAt = new Date()
      this.concurrency.release(task.concurrencyKey)
      this.closePaneForTask(task.id)
    } catch (err) {
      ompLog(`Task ${task.id}: status check error: ${String(err)}`)
      // If we can't check status, assume still running
    }
  }

  private async fetchSessionOutput(sessionID: string): Promise<string> {
    const rawResult = await this.client.messages({
      path: { id: sessionID },
    })
    // SDK returns { data: Array<{info, parts}>, request, response }.
    // unwrapData extracts .data → the messages array.
    const messages = unwrapData<unknown[]>(rawResult)
    return extractAssistantText(
      (Array.isArray(messages) ? messages : []) as Array<{
        info?: { role: string }
        parts?: Array<{ type: string; text?: string }>
      }>,
    )
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
