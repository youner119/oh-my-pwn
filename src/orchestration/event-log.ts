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

import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

import type { TaskStatus } from "./types"

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

/**
 * Orchestrator 의 status 변동 (Rev 7) — BG manager polling 안
 * `client.status()` 결과의 변동 시만 박힘. 사용자 prompt 대기 시
 * `"idle"`, 모델 응답 중 / active 영역 시 `"running"`. opencode 의 raw
 * `"busy"` / `"retry"` 는 `"running"` 으로 매핑 (기존 `isIdleStatus`
 * 패턴 일치). Initial status — `orchestrator_registered` 박힌 시점 =
 * `"running"` (fold 의 default).
 */
export interface OrchestratorStatusEvent extends EventCommon {
  type: "orchestrator_status"
  session_id: string
  status: "running" | "idle"
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
  | OrchestratorStatusEvent
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

/**
 * Read events.log and parse each JSONL line. Best-effort — corrupt lines
 * (JSON parse error) are skipped with console.error. Returns [] if the
 * file doesn't exist.
 *
 * Used by TUI consumer (T28) before fold. Read I/O separated from fold
 * for testability.
 */
export function readEventsLog(path: string): Event[] {
  if (!existsSync(path)) return []
  try {
    const content = readFileSync(path, "utf-8")
    const events: Event[] = []
    for (const line of content.split("\n")) {
      if (!line) continue
      try {
        events.push(JSON.parse(line) as Event)
      } catch (err) {
        console.error(`[event-log] line parse failed: ${String(err)} — line skipped`)
      }
    }
    return events
  } catch (err) {
    console.error(`[event-log] read failed: ${String(err)}`)
    return []
  }
}

/**
 * Fold events into a TreeJson snapshot (T28). Pure reducer — given the
 * same events sequence, always returns the same TreeJson. Used by the TUI
 * to re-render whenever the events.log mtime changes.
 *
 * Implementation: walks events in order, accumulating tasks Map +
 * orchestrators Map, then hands the result to `snapshotTasks` (legacy
 * function reused for hierarchy / parent resolution). Reconstructed
 * BackgroundTask uses placeholder `prompt: ""` + `concurrencyKey: agent`
 * since `snapshotTasks` only reads id / sessionID / agent / parentSessionID
 * / status / startedAt / createdAt / completedAt.
 */
export function foldEvents(events: Event[]): TreeJson {
  /**
   * Internal task accumulator. Subset of legacy BackgroundTask — only the
   * fields needed to produce a TreeNode. Standalone (no dependency on
   * BackgroundTask from "./types") since fold reconstructs state purely
   * from events.
   */
  type FoldTask = {
    id: string
    sessionID?: string
    agent: string
    parentSessionID: string
    status: TaskStatus
    /** task_started 이전엔 task_created.ts, 이후엔 task_started.ts. */
    startedAt: Date
    completedAt?: Date
  }

  const tasks = new Map<string, FoldTask>()
  const orchestrators = new Map<string, OrchestratorInfo>()
  /**
   * Orchestrator 별 마지막 status (Rev 7). `orchestrator_registered` 시
   * default `"running"` 박힘, `orchestrator_status` event 박힐 때마다
   * 갱신. fold output 의 orchestrator node status 가 이 Map 의 값 사용.
   */
  const orchestratorStatuses = new Map<string, "running" | "idle">()

  for (const e of events) {
    switch (e.type) {
      case "orchestrator_registered":
        orchestrators.set(e.session_id, {
          sessionID: e.session_id,
          agent: e.agent,
          challengeName: e.challenge_name,
          startedAt: new Date(e.ts),
        })
        // Initial status — orchestrator_status event 가 박힐 때까지 default
        orchestratorStatuses.set(e.session_id, "running")
        break
      case "orchestrator_status":
        orchestratorStatuses.set(e.session_id, e.status)
        break
      case "task_created":
        tasks.set(e.task_id, {
          id: e.task_id,
          parentSessionID: e.parent_session_id,
          agent: e.agent,
          status: "queued",
          startedAt: new Date(e.ts),
        })
        break
      case "task_started": {
        const task = tasks.get(e.task_id)
        if (task) {
          task.sessionID = e.session_id
          task.status = "running"
          task.startedAt = new Date(e.ts)
        }
        break
      }
      case "task_failed": {
        const task = tasks.get(e.task_id)
        if (task) {
          task.status = "failed"
          task.completedAt = new Date(e.ts)
        }
        break
      }
      case "task_cancelled": {
        const task = tasks.get(e.task_id)
        if (task) {
          task.status = "cancelled"
          task.completedAt = new Date(e.ts)
        }
        break
      }
      case "task_completed": {
        const task = tasks.get(e.task_id)
        if (task) {
          task.status = "completed"
          task.completedAt = new Date(e.ts)
        }
        break
      }
    }
  }

  // sessionID → taskID lookup for parent_task_id resolution.
  // Orchestrator sessions get sentinel IDs (`__orch_<sessionID>`) so
  // sub-agents whose parent_session_id == orchestrator's session_id
  // resolve to the orchestrator root node.
  const sessionToTask = new Map<string, string>()
  for (const orch of orchestrators.values()) {
    sessionToTask.set(orch.sessionID, orchestratorTaskId(orch.sessionID))
  }
  for (const task of tasks.values()) {
    if (task.sessionID) sessionToTask.set(task.sessionID, task.id)
  }

  const nodes: TreeNode[] = []

  // Orchestrator roots first (deterministic ordering by Map insertion).
  for (const orch of orchestrators.values()) {
    nodes.push({
      task_id: orchestratorTaskId(orch.sessionID),
      session_id: orch.sessionID,
      role: orch.agent,
      parent_task_id: null,
      status: orchestratorStatuses.get(orch.sessionID) ?? "running",
      started_at: orch.startedAt.toISOString(),
      challenge_name: orch.challengeName,
    })
  }

  for (const task of tasks.values()) {
    const node: TreeNode = {
      task_id: task.id,
      session_id: task.sessionID,
      role: task.agent,
      parent_task_id: sessionToTask.get(task.parentSessionID) ?? null,
      status: task.status,
      started_at: task.startedAt.toISOString(),
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

/**
 * Marker file path for the current process's events.log init. Used to
 * detect "this process already initialized" so re-entry (e.g. another
 * plugin invocation in the same process) doesn't truncate prior events.
 */
function initMarkerPath(): string {
  return join(treeJsonDir(), `.events-init-pid-${process.pid}`)
}

/**
 * Delete `.events-init-pid-<PID>` markers for PIDs other than the current
 * process. Prevents indefinite marker accumulation across reboots.
 */
function cleanupStalePidMarkers(): void {
  try {
    const dir = treeJsonDir()
    const entries = readdirSync(dir)
    for (const name of entries) {
      const match = name.match(/^\.events-init-pid-(\d+)$/)
      if (!match) continue
      const pid = Number(match[1])
      if (pid === process.pid) continue
      try {
        unlinkSync(join(dir, name))
      } catch {
        // marker disappeared between readdir + unlink — concurrent cleanup
      }
    }
  } catch {
    // dir read failed — non-fatal
  }
}

/**
 * Initialize events.log (T26). PID-based marker prevents same-process
 * re-init from truncating events written by other plugin invocations
 * (would defeat the race fix invariant).
 *
 * Strategy:
 *   1. If `.events-init-pid-<our-PID>` marker exists → another plugin
 *      invocation in the same process already initialized; skip.
 *   2. Otherwise: truncate events.log, create the marker, cleanup stale
 *      markers from previous PIDs.
 *
 * Called from BackgroundManager constructor when `enableEventLog = true`.
 */
export function initEventsLog(): void {
  ensureDir(treeJsonDir())
  const marker = initMarkerPath()
  if (existsSync(marker)) return
  writeFileSync(eventsLogPath(), "", "utf-8")
  writeFileSync(marker, "", "utf-8")
  cleanupStalePidMarkers()
}

// ─────────────────────────────────────────────────────────────────────
// TreeJson schema (TUI signal type, fold output)
// ─────────────────────────────────────────────────────────────────────

/**
 * TreeJson schema version. Stable across Rev 5 (snapshot) → Rev 6 (fold
 * output) — TUI render 코드는 schema 변화 없음.
 */
export const TREE_JSON_VERSION = 1

export interface TreeNode {
  task_id: string
  session_id?: string
  role: string
  /** Parent task id. null = root (Orchestrator session). */
  parent_task_id: string | null
  status: TaskStatus
  /** ISO 8601. */
  started_at: string
  /** ISO 8601. status 가 terminal (completed/failed/cancelled) 일 때만 set. */
  ended_at?: string
  /** Challenge name (orchestrator root 만 박힘). Multi-challenge 시 root 별 구별. */
  challenge_name?: string
}

/**
 * Orchestrator (top-level) session info — `orchestrator_registered` event
 * 의 payload 와 1:1. fold 가 events 로부터 재구성.
 */
export interface OrchestratorInfo {
  sessionID: string
  agent: string
  challengeName: string
  startedAt: Date
}

/**
 * Sentinel task_id for orchestrator root — sub-agent parent resolution
 * 용. sub-agent 의 `parent_session_id` 가 orchestrator 의 sessionID 와
 * 일치 시 이 sentinel id 를 parent_task_id 로 mapping.
 */
export function orchestratorTaskId(sessionID: string): string {
  return `__orch_${sessionID}`
}

export interface TreeJson {
  version: number
  /** ISO 8601 — snapshot 시각. */
  updated_at: string
  nodes: TreeNode[]
}

// ─────────────────────────────────────────────────────────────────────
// Filesystem helpers
// ─────────────────────────────────────────────────────────────────────

/**
 * OmP state directory resolve.
 *
 * 우선순위:
 *   1. `OMP_STATE_DIR` env var (사용자 override)
 *   2. `$XDG_STATE_HOME/omp`
 *   3. `~/.local/state/omp` (XDG 표준 fallback)
 *
 * Used by `eventsLogPath`, `initMarkerPath`, `cleanupStalePidMarkers`,
 * `initEventsLog`, `appendEventLine`.
 */
export function treeJsonDir(): string {
  const override = process.env.OMP_STATE_DIR
  if (override) return override
  const xdg = process.env.XDG_STATE_HOME
  if (xdg) return join(xdg, "omp")
  return join(homedir(), ".local", "state", "omp")
}

function ensureDir(dir: string): void {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
}
