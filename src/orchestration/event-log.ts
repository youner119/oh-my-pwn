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
 *
 * **Rev 8 — Multi-omp-run isolation (T35+).** `events.log` 단일 file 폐기,
 * `events-<OMP_INSTANCE_ID>.log` per-instance file. discriminator = `omp`
 * 런처 (zsh alias) 가 invocation 시점 `OMP_INSTANCE_ID="$(date +%s)-$$"`
 * 박음 → 두 omp 인스턴스 동시 실행 시 cross-talk 자체 소멸. retention =
 * `OMP_EVENTS_RETENTION_DAYS` (default 7). 위 Rev 6 의 PID-marker race fix
 * 는 *한 omp run 안의 plugin closure reload* 영역에 그대로 적용 (마커 scope
 * 가 PID → instance id 로 갱신).
 */

import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
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

/**
 * `startSession()` 성공 — task 가 session 에 배정되어 running 진입. **첫 이벤트**
 * (T34: `task_created` 폐기 — queued 는 미로그, session 이전이라 상관 키 없음).
 *
 * **이벤트 상관 키 = `session_id`** (T34 통일). 자식(submit/self-terminate)은
 * 자기 `ctx.sessionID`만 알고 `task_id`(부모 핸들)를 모르므로 모든 task 이벤트를
 * session_id 로 통일. `task_id`는 부모 API 핸들로 노드에 표시만 (fold →
 * `TreeNode.task_id`).
 */
export interface TaskStartedEvent extends EventCommon {
  type: "task_started"
  session_id: string
  task_id: string
  parent_session_id: string
  agent: string
  description: string
}

/**
 * 크래시 fallback — running session 이 submit 없이 종료 (T37 배선 예정).
 * launch-실패(pre-session, 부모가 task_id 도 못 받음)는 이벤트 미로그.
 */
export interface TaskFailedEvent extends EventCommon {
  type: "task_failed"
  session_id: string
  error: string
}

/** `cancel()` — submit 안 한 running 강제 중단 (긴급). */
export interface TaskCancelledEvent extends EventCommon {
  type: "task_cancelled"
  session_id: string
}

/**
 * Polling detected terminal state. `via`: `"idle"` = session status went idle,
 * `"gone"` = session disappeared from status map. 레거시 — T37 에서 idle≠terminal
 * 재작성 시 terminated/failed 로 대체 예정 (submit 프로토콜).
 */
export interface TaskCompletedEvent extends EventCommon {
  type: "task_completed"
  session_id: string
  via: "idle" | "gone"
}

/** 자식 submit — 결과 파일(`result_path`) 준비. `cycle` = 이 세션의 몇 번째 submit. */
export interface TaskSubmittedEvent extends EventCommon {
  type: "task_submitted"
  session_id: string
  cycle: number
  result_path: string
}

/** 부모 회수 — wait resolve 시 append. submitted vs consumed count 로 stale 방지. */
export interface TaskConsumedEvent extends EventCommon {
  type: "task_consumed"
  session_id: string
  cycle: number
}

/** 정상 종료 (self 또는 부모) — submit 이후. terminate=graceful, cancel 과 별개. */
export interface TaskTerminatedEvent extends EventCommon {
  type: "task_terminated"
  session_id: string
}

/**
 * Discriminated union of all event types. `switch (event.type) { ... }` in fold.
 * T34: 모든 task 이벤트가 `session_id` 상관 키.
 */
export type Event =
  | OrchestratorRegisteredEvent
  | OrchestratorStatusEvent
  | TaskStartedEvent
  | TaskFailedEvent
  | TaskCancelledEvent
  | TaskCompletedEvent
  | TaskSubmittedEvent
  | TaskConsumedEvent
  | TaskTerminatedEvent

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
 * Default value when `OMP_INSTANCE_ID` env is unset — preserves single-file
 * behavior for users who run `opencode` directly without the `omp` launcher.
 */
const DEFAULT_INSTANCE_ID = "default"

/** Default retention window for stale per-instance events.log + markers. */
const DEFAULT_RETENTION_DAYS = 7

/**
 * Per-omp-run discriminator (Rev 8). Set by the `omp` launcher (zsh alias)
 * before exec'ing opencode → inherited by both server plugin process and TUI
 * plugin process so each side resolves the same `events-<id>.log` file.
 *
 * Multi-instance isolation: two concurrent `omp` invocations get distinct
 * ids (e.g. `1717000000-12345`) → distinct event files → no cross-talk.
 * Fallback `"default"` keeps a single shared file for users not using the
 * launcher (backward compat with Rev 6/7 behavior).
 */
export function ompInstanceId(): string {
  return process.env.OMP_INSTANCE_ID || DEFAULT_INSTANCE_ID
}

/** Parse `OMP_EVENTS_RETENTION_DAYS` env (Rev 8). Default 7. */
function retentionDays(): number {
  const raw = process.env.OMP_EVENTS_RETENTION_DAYS
  if (!raw) return DEFAULT_RETENTION_DAYS
  const n = Number(raw)
  if (!Number.isFinite(n) || n < 0) return DEFAULT_RETENTION_DAYS
  return n
}

/**
 * Resolve the events.log absolute path (Rev 8 — per-instance). File name
 * encodes the omp-run discriminator from `OMP_INSTANCE_ID`. Honors
 * `OMP_STATE_DIR` / `XDG_STATE_HOME` / `~/.local/state/omp` for the
 * directory.
 */
export function eventsLogPath(): string {
  return join(treeJsonDir(), `events-${ompInstanceId()}.log`)
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
    /** task_id — 부모 API 핸들, TreeNode 표시용. */
    id: string
    /** = Map key (T34: session_id keying). */
    sessionID: string
    agent: string
    parentSessionID: string
    status: TaskStatus
    startedAt: Date
    completedAt?: Date
  }

  // T34: tasks keyed by session_id (이벤트 상관 키). task_created 폐기 →
  // task_started 가 첫 이벤트, queued 는 미로그.
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
      case "task_started":
        tasks.set(e.session_id, {
          id: e.task_id,
          sessionID: e.session_id,
          parentSessionID: e.parent_session_id,
          agent: e.agent,
          status: "running",
          startedAt: new Date(e.ts),
        })
        break
      case "task_failed": {
        const task = tasks.get(e.session_id)
        if (task) {
          task.status = "failed"
          task.completedAt = new Date(e.ts)
        }
        break
      }
      case "task_cancelled": {
        const task = tasks.get(e.session_id)
        if (task) {
          task.status = "cancelled"
          task.completedAt = new Date(e.ts)
        }
        break
      }
      case "task_completed": {
        const task = tasks.get(e.session_id)
        if (task) {
          task.status = "completed"
          task.completedAt = new Date(e.ts)
        }
        break
      }
      case "task_terminated": {
        const task = tasks.get(e.session_id)
        if (task) {
          task.status = "terminated"
          task.completedAt = new Date(e.ts)
        }
        break
      }
      // task_submitted / task_consumed: tree status 무변경 —
      // foldSubmissions ledger 전용 (매니저 wait-resolve).
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
 * Per-session submission ledger — the manager's read-model for wait-resolve
 * (T34, submit protocol). Distinct from `foldEvents` (TUI TreeJson): this
 * folds only `task_submitted` / `task_consumed` into per-session counts so the
 * manager can decide "is there an unconsumed submit?" cross-closure.
 */
export interface SubmissionLedger {
  /** Submissions for this session, sorted by cycle. */
  submissions: Array<{ cycle: number; result_path: string }>
  /** How many submits the parent has already consumed (wait-resolved). */
  consumedCount: number
}

/**
 * Fold events into a per-session submission ledger (T34). Pure reducer.
 *
 * Judgment (manager, T36): an UNCONSUMED submit exists when
 * `submissions.length > consumedCount`; the next unconsumed submission's file
 * is `submissions[consumedCount].result_path`. Counts are order-independent
 * (submit/consume are 1:1), and `cycle`-sorting makes file selection
 * deterministic even if events interleave across appends.
 */
export function foldSubmissions(events: Event[]): Map<string, SubmissionLedger> {
  const ledgers = new Map<string, SubmissionLedger>()
  const get = (sessionId: string): SubmissionLedger => {
    let ledger = ledgers.get(sessionId)
    if (!ledger) {
      ledger = { submissions: [], consumedCount: 0 }
      ledgers.set(sessionId, ledger)
    }
    return ledger
  }

  for (const e of events) {
    if (e.type === "task_submitted") {
      get(e.session_id).submissions.push({ cycle: e.cycle, result_path: e.result_path })
    } else if (e.type === "task_consumed") {
      get(e.session_id).consumedCount += 1
    }
  }

  for (const ledger of ledgers.values()) {
    ledger.submissions.sort((a, b) => a.cycle - b.cycle)
  }
  return ledgers
}

/**
 * Marker file path for the current omp-run's events.log init (Rev 8). Scope =
 * `OMP_INSTANCE_ID`. One marker per instance — within a single run, opencode
 * reloads the server plugin (same PID, same env) multiple times; the marker
 * prevents the second+ reload from truncating events written by the first.
 */
function initMarkerPath(): string {
  return join(treeJsonDir(), `.events-init-${ompInstanceId()}`)
}

/**
 * Prune stale per-instance event files + markers (Rev 8). Walks the state dir
 * for `events-*.log` + `.events-init-*` entries; deletes ones whose mtime is
 * older than `OMP_EVENTS_RETENTION_DAYS` (default 7). Our own instance's
 * files are always skipped regardless of mtime.
 *
 * Called from `initEventsLog()` at omp start. Cheap directory scan (≤ tens of
 * files in practice) — runs once per server plugin load.
 */
function pruneOldEventLogs(): void {
  let entries: string[]
  try {
    entries = readdirSync(treeJsonDir())
  } catch {
    return
  }

  const selfInstance = ompInstanceId()
  const cutoff = Date.now() - retentionDays() * 86_400 * 1000

  for (const name of entries) {
    const logMatch = name.match(/^events-(.+)\.log$/)
    const markerMatch = name.match(/^\.events-init-(.+)$/)
    const instance = logMatch?.[1] ?? markerMatch?.[1]
    if (!instance) continue
    if (instance === selfInstance) continue

    const full = join(treeJsonDir(), name)
    try {
      const stat = statSync(full)
      if (stat.mtimeMs >= cutoff) continue
      unlinkSync(full)
    } catch {
      // stat / unlink failed (file disappeared, permission) — non-fatal
    }
  }
}

/**
 * Initialize events.log (T26, Rev 8 multi-instance). Marker scope =
 * `OMP_INSTANCE_ID` so the same omp run's plugin closure reloads skip
 * re-init, while a fresh omp invocation (new instance id) truncates its own
 * file cleanly.
 *
 * Strategy:
 *   1. If `.events-init-<our-instance>` marker exists → already initialized
 *      in this omp run; skip (avoid truncating concurrent plugin closure
 *      reload's events).
 *   2. Otherwise: truncate our `events-<instance>.log`, create the marker,
 *      prune other instances' stale files (mtime > retention).
 *
 * Called from BackgroundManager constructor when `enableEventLog = true`.
 */
export function initEventsLog(): void {
  ensureDir(treeJsonDir())
  const marker = initMarkerPath()
  if (existsSync(marker)) return
  writeFileSync(eventsLogPath(), "", "utf-8")
  writeFileSync(marker, "", "utf-8")
  pruneOldEventLogs()
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
 * Used by `eventsLogPath`, `initMarkerPath`, `pruneOldEventLogs`,
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
