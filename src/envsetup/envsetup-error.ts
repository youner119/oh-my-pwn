/**
 * Discriminated error type raised by the T04 EnvSetup library.
 *
 * Each kind names a specific failure mode the EnvSetup pipeline can hit when
 * it touches docker, the filesystem, or the binary itself. The detail
 * payloads are intentionally rich — they include the candidate paths that
 * were tried, the exit code we observed, and (when relevant) a best-effort
 * listing of what _was_ found in the image. This is so that:
 *
 *   1. The user can read the journal entry and immediately diagnose the
 *      failure without re-running EnvSetup with extra logging.
 *   2. A future LLM-based wrapping agent (per the T04 pre-work decision in
 *      `.omc/state/current-task.md`) can reason about the failure and decide
 *      whether to retry, fall back to a different libc path, or escalate to
 *      the user. The error payloads are explicitly designed for this
 *      "library now, agent later" path.
 *
 * Non-fatal cases (like an unparsed glibc banner on a musl-based image, or a
 * Dockerfile that does not declare an EXPOSE port) are intentionally NOT
 * modelled as errors. Those modules return `null` / partial results and the
 * pipeline records "version unknown" / "remote unknown" in the journal.
 */

export type EnvSetupErrorKind =
  | "state-missing"
  | "docker-not-available"
  | "docker-build-failed"
  | "elf-parse-error"
  | "extraction-failed"
  | "libc-not-found"
  | "patchelf-not-available"
  | "patchelf-failed"

interface BaseDetail {
  message: string
  challengeDir: string
}

export interface StateMissingDetail extends BaseDetail {
  kind: "state-missing"
}

export interface DockerNotAvailableDetail extends BaseDetail {
  kind: "docker-not-available"
  /** Underlying spawn error code (e.g. "ENOENT", "EACCES"). */
  code?: string
}

export interface DockerBuildFailedDetail extends BaseDetail {
  kind: "docker-build-failed"
  exitCode: number
  imageTag: string
  dockerfilePath: string
  /** Absolute path to the captured build log under `.omp/logs/`. */
  buildLogPath: string
}

export interface ElfParseErrorDetail extends BaseDetail {
  kind: "elf-parse-error"
  binaryPath: string
  reason: string
}

export interface ExtractionFailedDetail extends BaseDetail {
  kind: "extraction-failed"
  imageTag: string
  /** Path inside the image we tried to copy out. */
  imagePath: string
  exitCode: number
  /** Up to ~1KB of `docker cp` stderr for the user to inspect. */
  stderr: string
}

export interface LibcNotFoundDetail extends BaseDetail {
  kind: "libc-not-found"
  imageTag: string
  /** Standard libc paths the extractor tried, in order. */
  candidatesTried: string[]
  /** Best-effort listing of common lib roots inside the image. */
  imageListing?: string[]
}

export interface PatchelfNotAvailableDetail extends BaseDetail {
  kind: "patchelf-not-available"
  /** Underlying spawn error code (e.g. "ENOENT"). */
  code?: string
}

export interface PatchelfFailedDetail extends BaseDetail {
  kind: "patchelf-failed"
  binaryPath: string
  exitCode: number
  /** Up to ~1KB of patchelf stderr for the user to inspect. */
  stderr: string
}

export type EnvSetupErrorDetail =
  | StateMissingDetail
  | DockerNotAvailableDetail
  | DockerBuildFailedDetail
  | ElfParseErrorDetail
  | ExtractionFailedDetail
  | LibcNotFoundDetail
  | PatchelfNotAvailableDetail
  | PatchelfFailedDetail

/**
 * Single error class for every recoverable EnvSetup failure.
 *
 * Use `err.kind` for narrow checks; `err.detail` for kind-specific fields.
 */
export class EnvSetupError extends Error {
  readonly kind: EnvSetupErrorKind
  readonly challengeDir: string
  readonly detail: EnvSetupErrorDetail

  constructor(detail: EnvSetupErrorDetail) {
    super(detail.message)
    this.name = "EnvSetupError"
    this.kind = detail.kind
    this.challengeDir = detail.challengeDir
    this.detail = detail
  }
}
