/**
 * Discriminated error type raised by `omp_load_challenge`.
 *
 * Post `.omc/specs/contract-load-detect-split.md` (D1), the loader is a thin
 * bootstrapper — it only validates that the challenge directory exists and
 * is a directory. Binary / Dockerfile / source detection moved to the
 * omp-setup agent (Phase 0), so the only failure modes the loader can raise
 * are filesystem-shape problems on the directory itself.
 */

export type ChallengeLoadErrorKind = "missing-dir" | "not-a-directory"

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

export type ChallengeLoadErrorDetail = MissingDirDetail | NotADirectoryDetail

/**
 * Single error class for every input-contract failure in the loader.
 *
 * Use `err.kind` for narrow checks; use `err.detail` for kind-specific fields.
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
