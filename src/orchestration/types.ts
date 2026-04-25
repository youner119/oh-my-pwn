/**
 * Parallel orchestration types.
 *
 * Ported from OmO's delegate-task infrastructure, simplified for OmP:
 * - No category resolver, tmux, skill injection, session cursor
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
  }): Promise<{ data?: { directory?: string } }>
}

/* ── Task types ───────────────────────────────────────────────────────── */

export type TaskStatus =
  | "queued"
  | "running"
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
}

export interface LaunchInput {
  parentSessionID: string
  agent: string
  description: string
  prompt: string
  runInBackground: boolean
  tools?: Record<string, boolean>
  model?: { providerID: string; modelID: string }
}

export interface TaskResult {
  taskId: string
  status: TaskStatus
  output?: string
  error?: string
}

/* ── Concurrency config ───────────────────────────────────────────────── */

export interface ConcurrencyConfig {
  /** Default max concurrent tasks per model key. 0 = unlimited. */
  defaultLimit: number
  /** Per-model overrides. Key = "providerID/modelID". 0 = unlimited. */
  modelLimits?: Record<string, number>
}

export const DEFAULT_CONCURRENCY_CONFIG: ConcurrencyConfig = {
  defaultLimit: 5,
}
