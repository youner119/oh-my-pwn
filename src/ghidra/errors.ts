/**
 * Discriminated error type for the T06 ghidra-mcp bridge.
 *
 * Follows the same pattern as
 * {@link import("../envsetup/envsetup-error").EnvSetupError}: each `kind`
 * names a specific failure mode, and the `detail` payload carries enough
 * context for the journal entry to be self-diagnosable.
 *
 * Non-fatal situations (e.g. a function that Ghidra cannot decompile) are
 * NOT modelled as errors — the bridge returns `null` / partial results and
 * lets the Reverser agent decide how to handle them.
 */

export type GhidraBridgeErrorKind =
  | "not-configured"
  | "connection-failed"
  | "connection-closed"
  | "tool-not-found"
  | "tool-call-failed"
  | "server-error"
  | "timeout"

interface BaseDetail {
  message: string
}

export interface NotConfiguredDetail extends BaseDetail {
  kind: "not-configured"
  /** What config field was missing or invalid. */
  field?: string
}

export interface ConnectionFailedDetail extends BaseDetail {
  kind: "connection-failed"
  /** Transport type that failed. */
  transport: "stdio" | "sse" | "http"
  /** Underlying error code (e.g. "ENOENT", "ECONNREFUSED"). */
  code?: string
}

export interface ConnectionClosedDetail extends BaseDetail {
  kind: "connection-closed"
}

export interface ToolNotFoundDetail extends BaseDetail {
  kind: "tool-not-found"
  /** The tool name that was not found on the server. */
  toolName: string
  /** Tools that ARE available (helps diagnosis). */
  availableTools: string[]
}

export interface ToolCallFailedDetail extends BaseDetail {
  kind: "tool-call-failed"
  toolName: string
  /** Server-reported error text, if any. */
  serverError?: string
}

export interface ServerErrorDetail extends BaseDetail {
  kind: "server-error"
  /** Raw error text from the server. */
  serverError?: string
}

export interface TimeoutDetail extends BaseDetail {
  kind: "timeout"
  /** What operation timed out. */
  operation: string
  /** Configured timeout in ms. */
  timeoutMs: number
}

export type GhidraBridgeErrorDetail =
  | NotConfiguredDetail
  | ConnectionFailedDetail
  | ConnectionClosedDetail
  | ToolNotFoundDetail
  | ToolCallFailedDetail
  | ServerErrorDetail
  | TimeoutDetail

/**
 * Single error class for every recoverable ghidra-mcp bridge failure.
 *
 * Use `err.kind` for narrow checks; `err.detail` for kind-specific fields.
 */
export class GhidraBridgeError extends Error {
  readonly kind: GhidraBridgeErrorKind
  readonly detail: GhidraBridgeErrorDetail

  constructor(detail: GhidraBridgeErrorDetail) {
    super(detail.message)
    this.name = "GhidraBridgeError"
    this.kind = detail.kind
    this.detail = detail
  }
}
