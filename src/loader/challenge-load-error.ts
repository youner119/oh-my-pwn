/**
 * Discriminated error type raised by the T03 challenge-folder loader.
 *
 * Each kind names a specific failure mode of the input contract so the caller
 * (assistant in M1, Orchestrator from T18 onward) can decide whether to:
 *
 * - prompt the user for disambiguation (`ambiguous-binary`),
 * - bail out with a precise message (`missing-dockerfile`, `missing-binary`),
 * - or surface a permissions/format problem
 *   (`binary-not-elf`, `binary-not-executable`).
 *
 * The loader itself never prompts the human directly — it only ever throws.
 * Human-in-the-loop disambiguation happens at the call site, which catches
 * this error and re-invokes `loadChallengeFolder` with an explicit
 * `{ binary }` option.
 */

export type ChallengeLoadErrorKind =
  | "missing-dir"
  | "not-a-directory"
  | "missing-dockerfile"
  | "missing-binary"
  | "ambiguous-binary"
  | "binary-not-elf"
  | "binary-not-executable"

interface BaseDetail {
  message: string
  challengeDir: string
}

export interface MissingDirDetail extends BaseDetail {
  kind: "missing-dir"
}

export interface NotADirectoryDetail extends BaseDetail {
  kind: "not-a-directory"
}

export interface MissingDockerfileDetail extends BaseDetail {
  kind: "missing-dockerfile"
}

export interface MissingBinaryDetail extends BaseDetail {
  kind: "missing-binary"
  /** The path the caller asked for (when an explicit hint was supplied). */
  binaryPath?: string
}

export interface AmbiguousBinaryDetail extends BaseDetail {
  kind: "ambiguous-binary"
  /** "none" → no ELF candidate found; "multiple" → more than one. */
  reason: "none" | "multiple"
  /** Absolute paths of every candidate the auto-detector saw. */
  candidates: string[]
}

export interface BinaryNotElfDetail extends BaseDetail {
  kind: "binary-not-elf"
  binaryPath: string
}

export interface BinaryNotExecutableDetail extends BaseDetail {
  kind: "binary-not-executable"
  binaryPath: string
}

export type ChallengeLoadErrorDetail =
  | MissingDirDetail
  | NotADirectoryDetail
  | MissingDockerfileDetail
  | MissingBinaryDetail
  | AmbiguousBinaryDetail
  | BinaryNotElfDetail
  | BinaryNotExecutableDetail

/**
 * Single error class for every input-contract failure in the loader.
 *
 * Use `err.kind` for narrow checks; use `err.detail` to access kind-specific
 * fields (e.g. `candidates` on `ambiguous-binary`).
 */
export class ChallengeLoadError extends Error {
  readonly kind: ChallengeLoadErrorKind
  readonly challengeDir: string
  readonly detail: ChallengeLoadErrorDetail

  constructor(detail: ChallengeLoadErrorDetail) {
    super(detail.message)
    this.name = "ChallengeLoadError"
    this.kind = detail.kind
    this.challengeDir = detail.challengeDir
    this.detail = detail
  }
}
