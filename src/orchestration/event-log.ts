/**
 * event-log.ts — TUI plugin 통신 채널.
 *
 * Spec: `.omc/specs/deep-interview-tui-plugin-integration.md` Rev 6
 * (events.log append + TUI fold, D2 재정의).
 *
 * **Stage:** Rev 6 race fix. T24 = Event types + serializeEvent helper. T25-T29
 * 가 기존 snapshotTasks / dumpTreeJson / initTreeJson 폐기 + appendEvent /
 * initEventsLog / readAndFoldEvents 도입. 현재 stage 는 *Event schema 추가 +
 * 기존 snapshot 영역 공존* — T29 graduate 시 snapshot 영역 삭제.
 *
 * Race 해소 메커니즘: 각 event line 에 `instance_id` (T27 — PID + module load
 * counter) 박음. Multi-instance 동시 append 가 자연 격리 (append-only +
 * `O_APPEND` + line < PIPE_BUF 4KB → atomic per line on Linux). 자세한 진단:
 * spec Rev 6 의 "Race 메커니즘 (정확한 진단)".
 */

import { appendFileSync, existsSync, mkdirSync, renameSync, writeFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

import type { BackgroundTask, TaskStatus } from "./types"

// ─────────────────────────────────────────────────────────────────────
// Event schema (Rev 6, T24)
// ─────────────────────────────────────────────────────────────────────

/**
 * Per-event schema version. Bump on breaking changes. Migration helper
 * inspects this on read (T28 fold). Per-event scope (not file header) so
 * future schema mix-and-match within the same file stays sound.
 */
export const EVENT_SCHEMA_VERSION = 1

/** Common fields across all event types. */
export interface EventCommon {
  version: typeof EVENT_SCHEMA_VERSION
  /** ISO 8601, UTC. */
  ts: string
  /**
   * PID + module load counter (T27). Same PID can have multiple plugin
   * invocations — each sub-agent session entry reloads the server plugin,
   * creating a fresh module instance. instance_id keeps them distinguishable.
   */
  instance_id: string
}

/** `registerOrchestrator()` — `omp_load_challenge` 첫 호출. */
export interface OrchestratorRegisteredEvent extends EventCommon {
  type: "orchestrator_registered"
  session_id: string
  agent: string
  challenge_name: string
}

/** `createTask()` — task queued. */
export interface TaskCreatedEvent extends EventCommon {
  type: "task_created"
  task_id: string
  parent_session_id: string
  agent: string
  description: string
}

/** `startSession()` 성공 — task transitioned to running. */
export interface TaskStartedEvent extends EventCommon {
  type: "task_started"
  task_id: string
  session_id: string
}

/** `launchAsync()` 실패 — session create / prompt failed. */
export interface TaskFailedEvent extends EventCommon {
  type: "task_failed"
  task_id: string
  error: string
}

/** `cancel()` — user / orchestrator aborted. */
export interface TaskCancelledEvent extends EventCommon {
  type: "task_cancelled"
  task_id: string
}

/**
 * Polling detected terminal state. `via` distinguishes the two completion
 * paths in `pollRunningTasks`: `"idle"` = session status went idle,
 * `"gone"` = session disappeared from status map (opencode cleaned up).
 */
export interface TaskCompletedEvent extends EventCommon {
  type: "task_completed"
  task_id: string
  via: "idle" | "gone"
}

/**
 * Discriminated union of all event types. `switch (event.type) { ... }`
 * for exhaustive narrowing in T28 fold.
 */
export type Event =
  | OrchestratorRegisteredEvent
  | TaskCreatedEvent
  | TaskStartedEvent
  | TaskFailedEvent
  | TaskCancelledEvent
  | TaskCompletedEvent

/** Discriminator literal type. */
export type EventType = Event["type"]

/**
 * Serialize one event to a single JSONL line (`\n` terminated).
 *
 * POSIX `O_APPEND` + line < PIPE_BUF (4KB) → atomic per line on Linux.
 * OmP event sizes ≤ ~1KB (error messages worst-case) → safe.
 *
 * Used by `appendEvent` (T25) to encode before `appendFileSync`.
 */
export function serializeEvent(event: Event): string {
  return `${JSON.stringify(event)}\n`
}

/**
 * Module-level counter — increments each plugin instance load. Combined
 * with PID gives a distinguishable instance_id across sub-agent session
 * entries (each entry creates a fresh module instance with its own counter
 * starting from 0).
 */
let moduleLoadCounter = 0

/**
 * Generate a fresh instance_id `<pid>-<counter>` (T27). Called once per
 * BackgroundManager constructor. Same PID can produce multiple IDs because
 * each plugin invocation reloads the module — each invocation gets its
 * own counter starting at 1.
 */
export function nextInstanceId(): string {
  moduleLoadCounter += 1
  return `${process.pid}-${moduleLoadCounter}`
}

/**
 * Resolve the events.log absolute path. Same directory as tree.json (legacy)
 * — only the file name differs. Honors `OMP_STATE_DIR` / `XDG_STATE_HOME`
 * / `~/.local/state/omp` resolution order (sibling of `treeJsonPath`).
 */
export function eventsLogPath(): string {
  return join(treeJsonDir(), "events.log")
}

/**
 * Append a single event line to events.log (POSIX `appendFileSync` +
 * `serializeEvent`). Best-effort — append failure is logged to console.error
 * and swallowed so primary flow (sub-agent spawn) is never blocked.
 *
 * Atomicity: POSIX `O_APPEND` + line < PIPE_BUF (4KB) → atomic per line on
 * Linux. Multi-instance concurrent appends naturally interleave without
 * partial-line corruption.
 *
 * Does NOT initialize the file — caller is expected to initialize on plugin
 * load (T26 / `initEventsLog`). If the file doesn't exist, `appendFileSync`
 * creates it (but prior process content may remain — that's why AC2 requires
 * explicit init).
 */
export function appendEventLine(event: Event): void {
  try {
    ensureDir(treeJsonDir())
    appendFileSync(eventsLogPath(), serializeEvent(event), "utf-8")
  } catch (err) {
    console.error(`[event-log] append failed: ${String(err)}`)
  }
}

// ─────────────────────────────────────────────────────────────────────
// Legacy: tree.json snapshot (Rev 3-5, T4-T6). T29 에서 삭제 예정.
// ─────────────────────────────────────────────────────────────────────

/** Schema version. Bump when breaking. */
export const TREE_JSON_VERSION = 1

export interface TreeNode {
  task_id: string
  session_id?: string
  role: string
  /** Parent task id. null = root (Orchestrator session). */
  parent_task_id: string | null
  status: TaskStatus
  /** ISO 8601. startedAt 없으면 createdAt fallback. */
  started_at: string
  /** ISO 8601. status 가 terminal (completed/failed/cancelled) 일 때만 set. */
  ended_at?: string
  /** Challenge name (orchestrator root 만 박힘). Multi-challenge 시 root 별 구별. */
  challenge_name?: string
}

/**
 * Orchestrator (top-level) session info — `omp_load_challenge` 호출 시 record.
 * BackgroundManager 의 tasks Map 에 없는 별개 root entry.
 */
export interface OrchestratorInfo {
  /** opencode session id. */
  sessionID: string
  /** agent name (보통 "omp-orchestrator"). ToolContext.agent 값. */
  agent: string
  /** challenge name (challenge_dir 의 basename 또는 사용자 명시). */
  challengeName: string
  /** ISO 8601 — load_challenge 호출 시점. */
  startedAt: Date
}

/** Sentinel task_id for orchestrator root — sub-agent parent resolution 용. */
export function orchestratorTaskId(sessionID: string): string {
  return `__orch_${sessionID}`
}

export interface TreeJson {
  version: number
  /** ISO 8601 — snapshot 시각. */
  updated_at: string
  nodes: TreeNode[]
}

/**
 * tree.json 디렉토리 resolve.
 *
 * 우선순위:
 *   1. `OMP_STATE_DIR` env var (사용자 override)
 *   2. `$XDG_STATE_HOME/omp`
 *   3. `~/.local/state/omp` (XDG 표준 fallback)
 */
export function treeJsonDir(): string {
  const override = process.env.OMP_STATE_DIR
  if (override) return override
  const xdg = process.env.XDG_STATE_HOME
  if (xdg) return join(xdg, "omp")
  return join(homedir(), ".local", "state", "omp")
}

/** tree.json 의 절대 경로. */
export function treeJsonPath(): string {
  return join(treeJsonDir(), "tree.json")
}

/**
 * Snapshot the current task map + orchestrator roots to a TreeJson payload.
 *
 * Orchestrator roots (from BackgroundManager.orchestrators) are added as
 * TreeNode entries with `task_id = orchestratorTaskId(sessionID)`,
 * `parent_task_id = null`, `status = "running"`. Sub-agent tasks whose
 * `parentSessionID` matches an orchestrator's `sessionID` get that root's
 * task_id as their `parent_task_id`.
 *
 * Maps BackgroundTask fields to schema:
 * - `id` → `task_id`
 * - `sessionID` → `session_id`
 * - `agent` → `role`
 * - `parentSessionID` → `parent_task_id` (orchestrators 의 sessionID 먼저 lookup,
 *   그 다음 다른 task 들의 sessionID lookup; 못 찾으면 null)
 * - `status` → `status`
 * - `startedAt ?? createdAt` → `started_at`
 * - `completedAt` → `ended_at` (있을 때만)
 */
export function snapshotTasks(
  tasks: Map<string, BackgroundTask>,
  orchestrators: Map<string, OrchestratorInfo> = new Map(),
): TreeJson {
  // sessionID → taskID lookup for parent resolution.
  // orchestrator session 이 우선 — sub-agent 의 parentSessionID 가 orchestrator
  // 의 sessionID 면 그 sentinel id 를 parent 로.
  const sessionToTask = new Map<string, string>()
  for (const orch of orchestrators.values()) {
    sessionToTask.set(orch.sessionID, orchestratorTaskId(orch.sessionID))
  }
  for (const task of tasks.values()) {
    if (task.sessionID) sessionToTask.set(task.sessionID, task.id)
  }

  const nodes: TreeNode[] = []

  // Orchestrator roots first (deterministic ordering by sessionID).
  for (const orch of orchestrators.values()) {
    nodes.push({
      task_id: orchestratorTaskId(orch.sessionID),
      session_id: orch.sessionID,
      role: orch.agent,
      parent_task_id: null,
      status: "running",
      started_at: orch.startedAt.toISOString(),
      challenge_name: orch.challengeName,
    })
  }

  for (const task of tasks.values()) {
    const startedAt = task.startedAt ?? task.createdAt
    const node: TreeNode = {
      task_id: task.id,
      session_id: task.sessionID,
      role: task.agent,
      parent_task_id: sessionToTask.get(task.parentSessionID) ?? null,
      status: task.status,
      started_at: startedAt.toISOString(),
    }
    if (task.completedAt) {
      node.ended_at = task.completedAt.toISOString()
    }
    nodes.push(node)
  }

  return {
    version: TREE_JSON_VERSION,
    updated_at: new Date().toISOString(),
    nodes,
  }
}

function ensureDir(dir: string): void {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
}

function atomicWrite(path: string, content: string): void {
  const tmpPath = `${path}.tmp`
  writeFileSync(tmpPath, content, "utf-8")
  renameSync(tmpPath, path)
}

/**
 * tree.json 을 빈 (nodes: []) 상태로 초기화.
 *
 * Plugin load 시점에 호출. 이전 세션의 잔여 tree 가 sidebar 에 보이지 않게.
 * 디렉토리 부재 시 mkdir.
 */
export function initTreeJson(): void {
  ensureDir(treeJsonDir())
  const empty: TreeJson = {
    version: TREE_JSON_VERSION,
    updated_at: new Date().toISOString(),
    nodes: [],
  }
  atomicWrite(treeJsonPath(), `${JSON.stringify(empty, null, 2)}\n`)
}

/**
 * tree.json 에 snapshot 박음. atomic.
 *
 * BackgroundManager 의 state transition 마다 호출. 실패는 console.error 만
 * (primary 흐름 막지 않음).
 */
export function dumpTreeJson(
  tasks: Map<string, BackgroundTask>,
  orchestrators: Map<string, OrchestratorInfo> = new Map(),
): void {
  try {
    ensureDir(treeJsonDir())
    const payload = snapshotTasks(tasks, orchestrators)
    atomicWrite(treeJsonPath(), `${JSON.stringify(payload, null, 2)}\n`)
  } catch (err) {
    console.error(`[event-log] write failed: ${String(err)}`)
  }
}
