/**
 * BackgroundManager — manages parallel sub-agent sessions.
 *
 * Simplified port of OmO's background-agent/manager.ts:
 * - No skill injection, no session cursor dedup
 * - No category resolver (direct agent name only)
 * - Supports both sync (blocking) and background (fire-and-forget) modes
 * - DI-friendly via OmpSessionClient interface
 *
 * Sub-agent 가시화는 Rev 5 의 TUI sidebar + Rev 6 의 events.log channel
 * 영역. tmux pane 영역은 T15-T18 (2026-05-23) 에서 폐기.
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
  EVENT_SCHEMA_VERSION,
  appendEventLine,
  eventsLogPath,
  foldSubmissions,
  initEventsLog,
  nextInstanceId,
  readEventsLog,
  type Event,
  type EventType,
  type OrchestratorInfo,
  type SubmissionLedger,
} from "./event-log"
import { EventEmitter } from "node:events"
import { appendFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs"
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
  return (
    status === "completed" ||
    status === "terminated" ||
    status === "failed" ||
    status === "cancelled"
  )
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
  concurrency?: { defaultLimit?: number; modelLimits?: Record<string, number> }
  /**
   * TUI plugin 통신용 tree.json dump 활성화. Plugin runtime 만 true, test 는
   * 기본 false (test 가 home dir 의 tree.json 덮어쓰지 않게).
   * Default: false.
   */
  enableEventLog?: boolean
}

export class BackgroundManager {
  private readonly client: OmpSessionClient
  private readonly directory: string
  private readonly tasks = new Map<string, BackgroundTask>()
  private readonly orchestrators = new Map<string, OrchestratorInfo>()
  /**
   * Per-orchestrator last seen status (Rev 7). polling 이 `client.status()`
   * 결과와 비교 — 변동 시만 `appendEvent("orchestrator_status", ...)` 박음
   * (event log noise 최소화). `registerOrchestrator` 시 initial `"running"`
   * 박음.
   */
  private readonly orchestratorStatuses = new Map<string, "running" | "idle">()
  private readonly concurrency: ConcurrencyManager
  private readonly enableEventLog: boolean
  /**
   * Per-instance identifier for events.log (T27). `<pid>-<counter>` — same
   * PID can produce multiple IDs across plugin invocations (each sub-agent
   * session entry reloads the server plugin → fresh module instance).
   */
  private readonly instanceId: string
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
    this.concurrency = new ConcurrencyManager(options.concurrency)
    this.enableEventLog = options.enableEventLog ?? false
    this.instanceId = nextInstanceId()
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
    if (this.enableEventLog) {
      initEventsLog()
    }
  }

  /**
   * Append a single event to events.log (Rev 6, T25). Best-effort — append
   * failure is logged but does not block the primary flow. `enableEventLog
   * = false` 면 no-op. ts / version / instance_id 는 이 method 가 자동
   * 채움 — caller 는 type + payload 만.
   *
   * Generic `T extends EventType` + `Extract<Event, { type: T }>` 가 type
   * 별 required payload 를 정확히 강제 (e.g. `task_completed` 의 `via`
   * field).
   */
  private appendEvent<T extends EventType>(
    type: T,
    payload: Omit<Extract<Event, { type: T }>, "version" | "ts" | "instance_id" | "type">,
  ): void {
    if (!this.enableEventLog) return
    // Call site narrows T to a literal (e.g. "task_completed") so the
    // payload param is type-checked per-type. Impl-side TS can't narrow T
    // back to a literal across the spread, so the assembled object widens
    // to a partial union — `as unknown as Event` is the documented escape.
    appendEventLine({
      version: EVENT_SCHEMA_VERSION,
      ts: new Date().toISOString(),
      instance_id: this.instanceId,
      type,
      ...payload,
    } as unknown as Event)
  }

  /**
   * Orchestrator (top-level) session 을 root TreeNode 로 record. `omp_load_challenge`
   * 첫 호출 시점에서 ToolContext.sessionID / agent + challenge name 박음. 같은
   * sessionID 재호출 시 idempotent (started_at 유지).
   *
   * Multi-challenge — orchestrator 마다 별개 sessionID. 각 root 가 tree.json
   * 에 별개 entry. sub-agent 의 parent_task_id resolution 시 orchestrator
   * 의 sessionID 가 우선 lookup.
   */
  registerOrchestrator(
    sessionID: string,
    agent: string,
    challengeName: string,
  ): void {
    if (!this.orchestrators.has(sessionID)) {
      this.orchestrators.set(sessionID, {
        sessionID,
        agent,
        challengeName,
        startedAt: new Date(),
      })
      this.orchestratorStatuses.set(sessionID, "running")
      this.appendEvent("orchestrator_registered", {
        session_id: sessionID,
        agent,
        challenge_name: challengeName,
      })
      // Rev 7 — orchestrator 만 있을 때도 polling 유지 (status 변동 감지).
      // sub-agent 가 launch 되기 전 / 모두 종료된 후의 orchestrator-only
      // 상태에서도 idle/running transition 박을 수 있도록.
      this.ensurePolling()
    }
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
    // Resolve `modelSpec` ("parent" / "providerID/modelID" / empty) to a
    // concrete model *before* createTask so the concurrency bucket key
    // reflects the model the child will actually run on. An explicit
    // `input.model` (programmatic callers) is used as a fallback.
    const resolvedModel =
      (await this.resolveModelSpec(input.modelSpec, input.parentSessionID)) ??
      input.model
    const resolvedInput: LaunchInput = {
      ...input,
      agent: resolvedAgent,
      model: resolvedModel,
    }

    const task = this.createTask(resolvedInput)
    await this.concurrency.acquire(task.concurrencyKey)

    try {
      await this.startSession(task, resolvedInput)
    } catch (err) {
      this.concurrency.release(task.concurrencyKey)
      task.status = "failed"
      task.error = String(err)
      // T34: launch-실패는 pre-session(session_id 없음)이고 부모가 task_id 도
      // 못 받음(throw) → 이벤트 미로그. task_failed 는 T37 크래시 fallback 용.
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
    // Identify pending tasks: known, not-yet-terminal, AND without an already-
    // waiting unconsumed submit (submit protocol — a submit resolves the wait
    // just like a terminal status).
    const ledgers = this.submissionLedgers()
    const pending = new Set<string>()
    for (const id of taskIds) {
      const t = this.tasks.get(id)
      if (t && !isTerminalStatus(t.status) && !this.hasUnconsumedSubmit(id, ledgers)) {
        pending.add(id)
      }
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
    // State-first: scan for already-resolved (terminal OR unconsumed submit) or
    // unknown, in input order.
    const ledgers = this.submissionLedgers()
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
      if (isTerminalStatus(t.status) || this.hasUnconsumedSubmit(id, ledgers)) {
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

  /** Read the per-session submission ledger from events.log (submit protocol). */
  private submissionLedgers(): Map<string, SubmissionLedger> {
    return foldSubmissions(readEventsLog(eventsLogPath()))
  }

  /**
   * True if the task's session has a submit the parent has not consumed yet.
   * `ledgers` may be passed to reuse a single fold across a batch.
   */
  private hasUnconsumedSubmit(taskId: string, ledgers?: Map<string, SubmissionLedger>): boolean {
    const task = this.tasks.get(taskId)
    if (!task?.sessionID) return false
    const ledger = (ledgers ?? this.submissionLedgers()).get(task.sessionID)
    return !!ledger && ledger.submissions.length > ledger.consumedCount
  }

  /**
   * Internal: build a TaskOutcome for a single id (submit protocol, D).
   * - Unconsumed submit → read+parse the submission file, inline as `result`,
   *   carry `result_path`, and append `task_consumed` (stale-resolve guard).
   * - No unconsumed submit → terminal outcome (crash fallback = failed, etc.).
   * - Unknown id → synthetic failed outcome.
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

    if (task.sessionID) {
      const ledger = this.submissionLedgers().get(task.sessionID)
      if (ledger && ledger.submissions.length > ledger.consumedCount) {
        const next = ledger.submissions[ledger.consumedCount]
        // Mark consumed FIRST so a racing poll / re-wait never re-resolves this
        // submit (even if the file read below fails on a poison file).
        this.appendEvent("task_consumed", { session_id: task.sessionID, cycle: next.cycle })
        try {
          const result = JSON.parse(readFileSync(next.result_path, "utf-8"))
          return {
            task_id: taskId,
            status: task.status,
            result_path: next.result_path,
            result,
          }
        } catch (err) {
          return {
            task_id: taskId,
            status: task.status,
            result_path: next.result_path,
            error: `submission read failed: ${String(err)}`,
          }
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
   *   2. Mark task `cancelled`, release concurrency slot.
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
    this.taskEvents.emit("done", task.id)
    // T34: session_id 키. queued 취소(session 없음)는 이벤트 미로그.
    if (task.sessionID) this.appendEvent("task_cancelled", { session_id: task.sessionID })
    return true
  }

  /**
   * Submit a result from a sub-agent (submit protocol, T35). Write-side
   * backing for the `omp_task_submit` tool (T41) — runs in the CHILD's manager
   * instance, which only knows the child's `sessionId` (no task_id / tasks-map
   * entry, since the task was created in the PARENT's manager).
   *
   * - `cycle` = (existing submission files for this session) + 1. File-count
   *   based (NOT event-based) so it is independent of `enableEventLog`.
   *   Submits within one session are sequential (agent submits once per turn,
   *   then idles), so no intra-session race.
   * - Result is written as pretty-printed JSON (Read line-cap safe) to an
   *   absolute path `<dir>/.omp/submissions/<sessionId>-<cycle>.json`.
   * - Appends a `task_submitted` event so the parent detects it cross-closure
   *   (the parent polls/folds events.log — T36).
   */
  submitResult(sessionId: string, result: unknown): { cycle: number; result_path: string } {
    const submissionsDir = join(this.directory, ".omp", "submissions")
    mkdirSync(submissionsDir, { recursive: true })

    let existing = 0
    try {
      const prefix = `${sessionId}-`
      existing = readdirSync(submissionsDir).filter(
        (name) => name.startsWith(prefix) && name.endsWith(".json"),
      ).length
    } catch {
      existing = 0
    }
    const cycle = existing + 1
    const resultPath = join(submissionsDir, `${sessionId}-${cycle}.json`)
    writeFileSync(resultPath, JSON.stringify(result, null, 2))

    this.appendEvent("task_submitted", {
      session_id: sessionId,
      cycle,
      result_path: resultPath,
    })

    ompLog(`submit: session ${sessionId} cycle ${cycle} → ${resultPath}`)
    return { cycle, result_path: resultPath }
  }

  /**
   * Resume an idle worker with a follow-up prompt (submit protocol, T38).
   * Re-prompts the SAME opencode session so the worker keeps its context —
   * used by the parent (orchestrator / SA) to drive a reusable worker
   * (e.g. exploiter retry loop).
   *
   * - Rejects unknown ids and terminal tasks (failed / cancelled / terminated).
   *   Allowed on `idle` OR `running` — the parent may resume right after
   *   consuming a submit, before the 3s poll has marked the task `idle`.
   * - Re-acquires a concurrency slot ONLY if the task was `idle` (T37 released
   *   it). A still-`running` task (poll lag) already holds its slot; acquiring
   *   again would double-count.
   * - Re-prompts with the original agent + model; tool restrictions are
   *   re-derived from the agent.
   */
  async resume(taskId: string, prompt: string): Promise<{ task_id: string; session_id: string }> {
    const task = this.tasks.get(taskId)
    if (!task) throw new Error(`unknown task_id: ${taskId}`)
    if (!task.sessionID) throw new Error(`task ${taskId} has no session to resume`)
    if (isTerminalStatus(task.status)) {
      throw new Error(`cannot resume terminal task ${taskId} (status: ${task.status})`)
    }

    // Only re-acquire if the slot was released (idle). Running = still held.
    if (task.status === "idle") {
      await this.concurrency.acquire(task.concurrencyKey)
    }
    task.status = "running"
    task.prompt = prompt

    const tools = getAgentToolRestrictions(task.agent)
    const parts: TextPart[] = [{ type: "text", text: prompt }]
    await this.client.promptAsync({
      path: { id: task.sessionID },
      body: {
        agent: task.agent,
        ...(task.model ? { model: task.model } : {}),
        tools,
        parts,
      },
    })

    this.ensurePolling()
    ompLog(`Task ${taskId}: resumed session ${task.sessionID}`)
    return { task_id: taskId, session_id: task.sessionID }
  }

  /** Shut down: cancel all waiters, stop polling. */
  shutdown(): void {
    this.stopPolling()
    this.concurrency.clear()
  }

  /* ── Internal ───────────────────────────────────────────────────────── */

  private createTask(input: LaunchInput): BackgroundTask {
    const id = generateTaskId()
    // Single-bucket fallback when `input.model` is absent (current omp_task_launch
    // path). Per-agent keys would partition limits across agents calling the same
    // provider, multiplying the effective cap by the number of agent kinds in flight.
    const concurrencyKey = input.model
      ? `${input.model.providerID}/${input.model.modelID}`
      : "default"
    const task: BackgroundTask = {
      id,
      parentSessionID: input.parentSessionID,
      agent: input.agent,
      description: input.description,
      prompt: input.prompt,
      status: "queued",
      createdAt: new Date(),
      concurrencyKey,
      // Stored so `resume` (T38) can re-prompt with the same model.
      model: input.model,
    }
    this.tasks.set(id, task)
    // T34: queued 는 미로그(session_id 이전) — 첫 이벤트는 startSession 의
    // task_started(모든 필드 병합).
    return task
  }

  /**
   * Resolve a raw `modelSpec` to a concrete `{ providerID, modelID }`.
   *
   *   - undefined / empty → `undefined` (child keeps its `agent.model` default).
   *   - "parent"          → query the parent session's current model
   *                         (`session.get().model`, where `.id` is the modelID).
   *                         If the parent has no resolved model yet, returns
   *                         `undefined` → safe fallback to the agent default.
   *   - "providerID/modelID" → split on the first "/".
   *
   * Throws on a malformed spec (no "/", or empty side) so a typo surfaces at
   * launch time rather than silently downgrading to the default.
   */
  private async resolveModelSpec(
    spec: string | undefined,
    parentSessionID: string,
  ): Promise<{ providerID: string; modelID: string } | undefined> {
    const trimmed = spec?.trim()
    if (!trimmed) return undefined

    if (trimmed === "parent") {
      try {
        const raw = await this.client.get({
          path: { id: parentSessionID },
          query: { directory: this.directory },
        })
        const parent = unwrapData<{
          model?: { id: string; providerID: string }
        }>(raw)
        if (parent?.model?.providerID && parent.model.id) {
          return {
            providerID: parent.model.providerID,
            modelID: parent.model.id,
          }
        }
      } catch {
        // Parent lookup failed — fall through to the agent default.
      }
      return undefined
    }

    const idx = trimmed.indexOf("/")
    if (idx <= 0 || idx === trimmed.length - 1) {
      throw new Error(
        `invalid model spec "${spec}" — expected "providerID/modelID" ` +
          `(e.g. "openai/gpt-5.5"), "parent", or empty for the agent default.`,
      )
    }
    return {
      providerID: trimmed.slice(0, idx),
      modelID: trimmed.slice(idx + 1),
    }
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
    // Sub-agents auto-allow tool permissions so they never block on technical
    // approvals. `webfetch` / `websearch` are allow — VH / SA / Exploiter
    // benefit from external knowledge (CVE / public writeup / libc / kernel
    // semantics) beyond our bundled knowledge/. `question` is `ask` (not
    // deny) so user-directed questions propagate via opencode's parent
    // chain to reach the user at the orchestrator/primary session.
    // See .omc/research/subagent-permission-forward.md.
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
          { permission: "webfetch", action: "allow", pattern: "*" },
          { permission: "websearch", action: "allow", pattern: "*" },
          { permission: "question", action: "ask", pattern: "*" },
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
    this.appendEvent("task_started", {
      session_id: sessionID,
      task_id: task.id,
      parent_session_id: task.parentSessionID,
      agent: task.agent,
      description: task.description,
    })

    // Build tool restrictions
    const tools: Record<string, boolean> = {
      ...getAgentToolRestrictions(input.agent),
      ...(input.tools ?? {}),
    }

    // Fire prompt.
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

    ompLog(`Task ${task.id}: session ${sessionID} created for @${input.agent}`)
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
      // Submit protocol (T36): fold events.log once per tick so a submit from a
      // sub-agent's own plugin closure is detected cross-closure.
      const ledgers = this.submissionLedgers()

      for (const task of this.tasks.values()) {
        if (task.status !== "running" || !task.sessionID) continue

        // A new unconsumed submit wakes any waiter (task stays running — it is
        // still alive, possibly idle-awaiting-resume). Harmless no-op if no
        // waiter; stops once buildOutcome appends task_consumed.
        const ledger = ledgers.get(task.sessionID)
        if (ledger && ledger.submissions.length > ledger.consumedCount) {
          this.taskEvents.emit("done", task.id)
        }

        // T37: has this session ever submitted a result? Discriminates
        // idle-awaiting-resume (submitted) from crash fallback (never submitted).
        const hasSubmitted = !!ledger && ledger.submissions.length > 0
        const sessionStatus = statuses[task.sessionID]

        if (!sessionStatus) {
          // Session vanished from the status map (opencode cleaned it up).
          // Terminal — a gone session cannot be resumed. > 10s guard avoids a
          // startup race where the session isn't in the map yet.
          if (task.startedAt && Date.now() - task.startedAt.getTime() > 10000) {
            if (hasSubmitted) {
              task.status = "completed"
              task.completedAt = new Date()
              this.concurrency.release(task.concurrencyKey)
              void this.dumpTranscript(task)
              this.taskEvents.emit("done", task.id)
              this.appendEvent("task_completed", { session_id: task.sessionID!, via: "gone" })
              ompLog(`Task ${task.id}: session gone (had submitted) → completed`)
            } else {
              task.status = "failed"
              task.error = "session gone without submitting"
              task.completedAt = new Date()
              this.concurrency.release(task.concurrencyKey)
              void this.dumpTranscript(task)
              this.taskEvents.emit("done", task.id)
              this.appendEvent("task_failed", {
                session_id: task.sessionID!,
                error: "session gone without submitting",
              })
              ompLog(`Task ${task.id}: session gone without submit → failed`)
            }
          }
          continue
        }

        // Any non-idle status (busy, retry) → still working, keep waiting.
        if (!isIdleStatus(sessionStatus.type)) continue

        // T37: idle judgment. Submit-then-idle is NOT terminal — the worker is
        // alive, awaiting parent resume/terminate. Idle-without-submit is the
        // crash fallback.
        if (hasSubmitted) {
          // Awaiting resume: release the slot (not computing), but do NOT emit
          // done / dump — the submit already resolved the parent, and the
          // session must stay alive for a possible resume.
          task.status = "idle"
          this.concurrency.release(task.concurrencyKey)
          ompLog(`Task ${task.id}: submitted → idle (awaiting resume)`)
        } else {
          // Crash fallback — finished a turn without ever submitting.
          task.status = "failed"
          task.error = "session idle without submitting"
          task.completedAt = new Date()
          this.concurrency.release(task.concurrencyKey)
          void this.dumpTranscript(task)
          this.taskEvents.emit("done", task.id)
          this.appendEvent("task_failed", {
            session_id: task.sessionID!,
            error: "session idle without submitting",
          })
          ompLog(`Task ${task.id}: idle without submit → failed`)
        }
      }

      // Orchestrator status 추적 (Rev 7) — 변동 시만 event 박음.
      for (const orch of this.orchestrators.values()) {
        const sdkStatus = statuses[orch.sessionID]
        if (!sdkStatus) continue // session disappeared — ignore (status 유지)
        const newStatus = isIdleStatus(sdkStatus.type) ? "idle" : "running"
        const oldStatus =
          this.orchestratorStatuses.get(orch.sessionID) ?? "running"
        if (newStatus !== oldStatus) {
          this.orchestratorStatuses.set(orch.sessionID, newStatus)
          this.appendEvent("orchestrator_status", {
            session_id: orch.sessionID,
            status: newStatus,
          })
        }
      }

      // Stop polling if no running tasks AND no orchestrators remain.
      // Rev 7 — orchestrator 가 있는 동안 polling 유지 (idle 대기 중에도
      // 다음 busy transition 감지).
      let hasRunning = false
      for (const task of this.tasks.values()) {
        if (task.status === "running") {
          hasRunning = true
          break
        }
      }
      if (!hasRunning && this.orchestrators.size === 0) this.stopPolling()
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
}
