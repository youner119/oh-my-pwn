/**
 * Parallel orchestration types.
 *
 * Ported from OmO's delegate-task infrastructure, simplified for OmP:
 * - No category resolver, skill injection, session cursor
 * - DI-friendly: OmpSessionClient interface for testability
 */

/* ── SDK client interface (subset of OpencodeClient) ──────────────────── */

/** Minimal text part for session.promptAsync. */
export interface TextPart {
  type: "text"
  text: string
}

/**
 * Minimal session client interface — only the methods OmP orchestration uses.
 *
 * Maps to opencode SDK's `client.session.*` namespace. The BackgroundManager
 * receives `client.session` (not the top-level client) so we can test with
 * a simple fake without mocking the full OpencodeClient.
 */
export interface OmpSessionClient {
  create(params: {
    body: Record<string, unknown>
    query?: Record<string, unknown>
  }): Promise<{ data: { id: string } }>

  promptAsync(params: {
    path: { id: string }
    body: Record<string, unknown>
  }): Promise<unknown>

  /** Returns all session statuses. Key = sessionID. */
  status(): Promise<Record<string, { type: string }>>

  /** Fetch messages from a session. */
  messages(params: {
    path: { id: string }
  }): Promise<{
    data: Array<{
      info?: { role: string }
      parts?: Array<{ type: string; text?: string }>
    }>
  }>

  /** Get session metadata (directory, parentID, etc.). */
  get(params: {
    path: { id: string }
    query?: Record<string, unknown>
  }): Promise<{
    data?: {
      directory?: string
      /** Session's current model (opencode session Info `model`). `id` is the
       * modelID. Populated by the ModelSwitched projector once the session has
       * been prompted — used to resolve `modelSpec: "parent"`. */
      model?: { id: string; providerID: string; variant?: string }
    }
  }>

  /**
   * Abort a running session — used by BackgroundManager.cancel() (T4).
   * Maps to opencode SDK's `client.session.abort` (POST /session/{id}/abort).
   * Errors are swallowed by the caller since the session may have already
   * finished between the cancel decision and the abort call.
   */
  abort(params: {
    path: { id: string }
    query?: Record<string, unknown>
  }): Promise<unknown>
}

/* ── Task types ───────────────────────────────────────────────────────── */

/**
 * Task lifecycle status.
 *
 * Submit protocol (spec `deep-interview-subagent-submit-protocol.md`):
 * - `queued` / `running` — pre-terminal work.
 * - `idle` — finished a turn, session alive, awaiting parent resume/terminate
 *   (non-terminal). A worker that submitted then paused sits here.
 * - `terminated` — graceful close after result was submitted (self or parent).
 *   The normal end of a worker's life.
 * - `failed` — crashed / ended without submitting (crash fallback).
 * - `cancelled` — emergency abort of unsubmitted running work.
 *
 * `completed` is DEPRECATED — legacy "session went idle = done" marker from the
 * pre-submit model. Retained until the BackgroundManager migration (C2, T36/T37)
 * replaces its uses with `idle` / `terminated` / `failed`, then removed.
 */
export type TaskStatus =
  | "queued"
  | "running"
  | "idle"
  | "terminated"
  | "completed"
  | "failed"
  | "cancelled"

export interface BackgroundTask {
  id: string
  sessionID?: string
  parentSessionID: string
  agent: string
  description: string
  prompt: string
  status: TaskStatus
  createdAt: Date
  startedAt?: Date
  completedAt?: Date
  error?: string
  concurrencyKey: string
  /**
   * Resolved model for the child session. Stored at launch so `resume` (T38)
   * can re-prompt the same session with the same model.
   */
  model?: { providerID: string; modelID: string }
}

export interface LaunchInput {
  parentSessionID: string
  agent: string
  description: string
  prompt: string
  tools?: Record<string, boolean>
  /**
   * Resolved model for the child session. When set, passed to the prompt as
   * `input.model`, which wins opencode's `input.model ?? agent.model ??
   * currentModel` resolution. Usually derived from `modelSpec` (below); a
   * direct programmatic caller may set it instead.
   */
  model?: { providerID: string; modelID: string }
  /**
   * Raw model directive from the `omp_task_launch` tool, resolved to `model`
   * in `launchAsync` before the task is created:
   *   - undefined / empty → leave `model` unset → child uses its own
   *     `agent.model` default.
   *   - "parent"          → inherit the parent session's current model.
   *   - "providerID/modelID" (e.g. "openai/gpt-5.5") → that exact model.
   */
  modelSpec?: string
}

/* ── 4-tool surface result types ──────────────────────────────────────── */
/* Returned by `omp_task_launch` / `_wait_all` / `_wait_any` / `_cancel`.    */

/** Returned by `omp_task_launch` — fire-and-forget. */
export interface LaunchResult {
  task_id: string
  session_id: string
}

/**
 * Single task outcome observed by wait_*.
 *
 * Submit protocol result channel (D — manager inline): on a successful
 * submit-resolve, the manager reads+parses the submission file and inlines the
 * parsed object as `result`, plus carries `result_path` (our
 * `.omp/submissions/<session>-<cycle>.json`). `result_path` is declared BEFORE
 * `result` and MUST be serialized first (buildOutcome key order) so it survives
 * opencode's head-truncation preview when a large `result` gets filed. `error`
 * is set for failed/cancelled (crash fallback = failed, no result).
 *
 * `output` is DEPRECATED — the pre-submit assistant-text channel. Retained
 * until the BackgroundManager migration (C2, T36) fills `result`/`result_path`
 * instead, then removed.
 */
export interface TaskOutcome {
  task_id: string
  status: TaskStatus
  /** Path to our submission file. Serialize before `result` (truncation-survival). */
  result_path?: string
  /** Parsed submission JSON, inlined by the manager (D). Agent-defined shape. */
  result?: unknown
  output?: string
  error?: string
}

/** Returned by `omp_task_wait_all` — results[] preserves input task_ids order. */
export interface WaitAllResult {
  results: TaskOutcome[]
}

/**
 * Returned by `omp_task_wait_any` — first task to reach an unconsumed submit OR
 * terminal (whichever first) + remaining ids. See the submit protocol spec.
 */
export interface WaitAnyResult extends TaskOutcome {
  remaining_ids: string[]
}

/** Returned by `omp_task_cancel`. `not_found` includes already-terminal ids. */
export interface CancelResult {
  cancelled: string[]
  not_found: string[]
}

/* ── Concurrency config ───────────────────────────────────────────────── */

export interface ConcurrencyConfig {
  /** Default max concurrent tasks per model key. 0 = unlimited. */
  defaultLimit: number
  /** Per-model overrides. Key = "providerID/modelID". 0 = unlimited. */
  modelLimits?: Record<string, number>
}

export const DEFAULT_CONCURRENCY_CONFIG: ConcurrencyConfig = {
  defaultLimit: 20,
}
