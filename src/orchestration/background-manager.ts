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
  LaunchResult,
  OmpSessionClient,
  TaskOutcome,
  TaskStatus,
  TextPart,
  WaitAllResult,
  WaitAnyResult,
} from "./types"
import { ConcurrencyManager } from "./concurrency"
import { resolveAgent } from "./agent-resolver"
import { getAgentToolRestrictions } from "./agent-tool-restrictions"
import {
  isInsideTmux,
  spawnSubagentPane,
  closeTmuxPane,
  resetPaneTracking,
  findPaneBySession,
} from "./tmux"
import { dumpTreeJson, initTreeJson } from "./tree-dump"
import { EventEmitter } from "node:events"
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs"
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

/** Task is in a terminal state (completed / failed / cancelled). */
function isTerminalStatus(status: TaskStatus): boolean {
  return status === "completed" || status === "failed" || status === "cancelled"
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
  /**
   * TUI plugin 통신용 tree.json dump 활성화. Plugin runtime 만 true, test 는
   * 기본 false (test 가 home dir 의 tree.json 덮어쓰지 않게).
   * Default: false.
   */
  enableTreeDump?: boolean
}

export class BackgroundManager {
  private readonly client: OmpSessionClient
  private readonly directory: string
  private readonly serverUrl?: string
  private readonly tasks = new Map<string, BackgroundTask>()
  private readonly paneIds = new Map<string, string>() // taskId → tmux paneId
  private readonly sessionPaneIds = new Map<string, string>() // sessionID → tmux paneId
  private readonly concurrency: ConcurrencyManager
  private readonly enableTreeDump: boolean
  private pollingInterval?: ReturnType<typeof setInterval>
  private pollingInFlight = false
  /**
   * Emits "done" with the taskId when a task transitions to a terminal
   * status (completed / failed / cancelled). Consumed by waitAll / waitAny
   * (added in T6) to resolve their Promises immediately instead of polling.
   */
  readonly taskEvents = new EventEmitter()

  constructor(options: BackgroundManagerOptions) {
    this.client = options.client
    this.directory = options.directory
    this.serverUrl = options.serverUrl
    this.concurrency = new ConcurrencyManager(options.concurrency)
    this.enableTreeDump = options.enableTreeDump ?? false
    // wait_all/wait_any may attach many listeners concurrently (e.g., VH
    // ensemble + SA race at the same time). Default cap of 10 would warn.
    this.taskEvents.setMaxListeners(0)

    // Initialize log file at .omp/logs/orchestration.log
    try {
      const logsDir = join(this.directory, ".omp", "logs")
      mkdirSync(logsDir, { recursive: true })
      logPath = join(logsDir, "orchestration.log")
      ompLog("BackgroundManager initialized")
    } catch {
      // If directory doesn't exist yet (no challenge loaded), skip logging
    }

    // Initialize tree.json (empty) at plugin load time so TUI plugin watcher
    // sees a clean state (previous session's tree 잔여 사라짐).
    if (this.enableTreeDump) {
      initTreeJson()
    }
  }

  /**
   * tree.json snapshot dump. Best-effort — failure 는 console.error 로만 log,
   * primary 흐름 (sub-agent spawn) 막지 않음. enableTreeDump=false 면 no-op.
   */
  private dumpTree(): void {
    if (!this.enableTreeDump) return
    dumpTreeJson(this.tasks)
  }

  /**
   * Launch a sub-agent task in fire-and-forget mode.
   *
   * Backing impl for the `omp_task_launch` tool. Resolves the agent
   * category alias to a concrete agent name via `resolveAgent`, creates
   * the opencode child session, fires the prompt, and returns
   * `{ task_id, session_id }`. The session runs asynchronously; observe
   * its outcome via `waitAll` / `waitAny` or `getTask`.
   *
   * On session creation failure, the task is marked `failed` in the
   * tasks map (state consistency) and the error is rethrown to the caller.
   */
  async launchAsync(input: LaunchInput): Promise<LaunchResult> {
    const resolvedAgent = resolveAgent(input.agent)
    const resolvedInput: LaunchInput = { ...input, agent: resolvedAgent }

    const task = this.createTask(resolvedInput)
    await this.concurrency.acquire(task.concurrencyKey)

    try {
      await this.startSession(task, resolvedInput)
    } catch (err) {
      this.concurrency.release(task.concurrencyKey)
      task.status = "failed"
      task.error = String(err)
      this.dumpTree()
      throw err
    }

    this.ensurePolling()
    return { task_id: task.id, session_id: task.sessionID! }
  }

  /**
   * Wait until ALL tasks reach a terminal status (T6).
   *
   * - Returns `results[]` in the same order as input `taskIds`.
   * - Unknown task_ids become synthetic failed outcomes (A1 — graceful).
   * - Outputs for completed tasks are fetched in parallel via Promise.all
   *   (B1).
   * - State-first: if all tasks are already terminal, returns immediately.
   */
  async waitAll(taskIds: string[]): Promise<WaitAllResult> {
    // Identify pending tasks (known + not-yet-terminal).
    const pending = new Set<string>()
    for (const id of taskIds) {
      const t = this.tasks.get(id)
      if (t && !isTerminalStatus(t.status)) pending.add(id)
    }

    if (pending.size > 0) {
      await new Promise<void>((resolve) => {
        const handler = (taskId: string) => {
          if (pending.has(taskId)) {
            pending.delete(taskId)
            if (pending.size === 0) {
              this.taskEvents.off("done", handler)
              resolve()
            }
          }
        }
        this.taskEvents.on("done", handler)
      })
    }

    const results = await Promise.all(taskIds.map((id) => this.buildOutcome(id)))
    return { results }
  }

  /**
   * Wait until ANY of the given tasks reaches a terminal status (T6).
   *
   * - Returns the first task to reach terminal + `remaining_ids` (input
   *   order preserved, first task removed).
   * - State-first: scans `taskIds` in input order; the first
   *   already-terminal id wins.
   * - Unknown task_ids (A1) become synthetic failed outcomes. If
   *   encountered first in iteration order, they "win" as first complete.
   * - Cancellation and failure both count as first-complete (C, spec L75).
   */
  async waitAny(taskIds: string[]): Promise<WaitAnyResult> {
    // State-first: scan for already-terminal (or unknown) in input order.
    for (const id of taskIds) {
      const t = this.tasks.get(id)
      if (!t) {
        return {
          task_id: id,
          status: "failed",
          error: `unknown task_id: ${id}`,
          remaining_ids: taskIds.filter((x) => x !== id),
        }
      }
      if (isTerminalStatus(t.status)) {
        const outcome = await this.buildOutcome(id)
        return { ...outcome, remaining_ids: taskIds.filter((x) => x !== id) }
      }
    }

    // All running — subscribe.
    const watching = new Set(taskIds)
    const firstId = await new Promise<string>((resolve) => {
      const handler = (taskId: string) => {
        if (watching.has(taskId)) {
          this.taskEvents.off("done", handler)
          resolve(taskId)
        }
      }
      this.taskEvents.on("done", handler)
    })

    const outcome = await this.buildOutcome(firstId)
    return { ...outcome, remaining_ids: taskIds.filter((x) => x !== firstId) }
  }

  /**
   * Internal: build a TaskOutcome for a single id (T6 helper).
   * - Completed → fetches assistant text via fetchSessionOutput.
   * - Failed / cancelled → returns error text without fetch.
   * - Unknown id → synthetic failed outcome (A1).
   * - Fetch failure → marks as completed with error message.
   */
  private async buildOutcome(taskId: string): Promise<TaskOutcome> {
    const task = this.tasks.get(taskId)
    if (!task) {
      return {
        task_id: taskId,
        status: "failed",
        error: `unknown task_id: ${taskId}`,
      }
    }
    if (task.status === "completed" && task.sessionID) {
      try {
        const output = await this.fetchSessionOutput(task.sessionID)
        return { task_id: taskId, status: task.status, output }
      } catch (err) {
        return {
          task_id: taskId,
          status: task.status,
          error: `output fetch failed: ${String(err)}`,
        }
      }
    }
    return {
      task_id: taskId,
      status: task.status,
      ...(task.error ? { error: task.error } : {}),
    }
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

  /**
   * Cancel a task by ID. The API surface for the `omp_task_cancel`
   * tool. Idempotent: returns false for unknown ids or tasks already in
   * a terminal state.
   *
   * Steps:
   *   1. Best-effort POST /session/{id}/abort (errors swallowed — session
   *      may have finished between status check and abort).
   *   2. Mark task `cancelled`, release concurrency slot, close tmux pane.
   *   3. Emit "done" so any pending waitAll/waitAny treats it as a first-
   *      complete candidate.
   */
  async cancel(taskId: string): Promise<boolean> {
    const task = this.tasks.get(taskId)
    if (!task) return false
    if (task.status !== "running" && task.status !== "queued") return false

    if (task.sessionID) {
      try {
        await this.client.abort({ path: { id: task.sessionID } })
      } catch (err) {
        ompLog(`Task ${taskId}: abort RPC failed, marking cancelled anyway: ${String(err)}`)
      }
    }

    task.status = "cancelled"
    task.completedAt = new Date()
    this.concurrency.release(task.concurrencyKey)
    this.closePaneForTask(task.id)
    this.taskEvents.emit("done", task.id)
    this.dumpTree()
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
      // Reset pane tracking when all panes are closed so the next round
      // starts fresh instead of trying to split a dead pane.
      if (this.paneIds.size === 0) {
        resetPaneTracking()
      }
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
    this.dumpTree()
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
    this.dumpTree()

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
      // Fast path — parent pane was spawned by *this* manager instance
      // (e.g. Orchestrator launching VH / SA). Cross-instance lookups
      // (an SA in its own plugin instance launching an Exploiter) miss
      // here because each plugin invocation gets its own
      // `sessionPaneIds` Map; fall back to querying tmux itself, which
      // is the only store shared across plugin instances.
      let parentPaneId = this.sessionPaneIds.get(input.parentSessionID)
      if (!parentPaneId) {
        parentPaneId = await findPaneBySession(input.parentSessionID)
      }
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
            void this.dumpTranscript(task)
            this.taskEvents.emit("done", task.id)
            this.dumpTree()
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
        void this.dumpTranscript(task)
        this.taskEvents.emit("done", task.id)
        this.dumpTree()
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

  /**
   * Persist a sub-agent's full conversation transcript to
   * `<challenge_dir>/.omp/logs/agents/<task_id>__<agent>__<desc>.json`.
   *
   * Called once when the task transitions to "completed". Captures raw
   * opencode messages (user prompt, assistant parts, tool calls + results)
   * so the full reasoning trail is auditable after the pipeline finishes.
   *
   * Errors are swallowed and logged — transcript loss must never break the
   * pipeline.
   */
  private async dumpTranscript(task: BackgroundTask): Promise<void> {
    if (!task.sessionID) return
    try {
      const rawResult = await this.client.messages({
        path: { id: task.sessionID },
      })
      const messages = unwrapData<unknown[]>(rawResult)
      const logsDir = join(this.directory, ".omp", "logs", "agents")
      mkdirSync(logsDir, { recursive: true })
      const safeDesc = task.description
        .replace(/[^A-Za-z0-9_.-]/g, "_")
        .slice(0, 60)
      const filename = `${task.id}__${task.agent}__${safeDesc}.json`
      const payload = {
        task_id: task.id,
        agent: task.agent,
        description: task.description,
        session_id: task.sessionID,
        parent_session_id: task.parentSessionID,
        status: task.status,
        created_at: task.createdAt.toISOString(),
        started_at: task.startedAt?.toISOString(),
        completed_at: task.completedAt?.toISOString(),
        duration_ms:
          task.startedAt && task.completedAt
            ? task.completedAt.getTime() - task.startedAt.getTime()
            : undefined,
        messages: Array.isArray(messages) ? messages : [],
      }
      writeFileSync(
        join(logsDir, filename),
        JSON.stringify(payload, null, 2),
      )
      ompLog(`Task ${task.id}: transcript dumped to ${filename}`)
    } catch (err) {
      ompLog(`Task ${task.id}: transcript dump failed: ${String(err)}`)
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
