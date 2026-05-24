/**
 * `omp_load_challenge` loader (barrel).
 *
 * Public surface for the loader. The loader is a thin bootstrapper per
 * `.omc/specs/contract-load-detect-split.md` (D1) — `binary-detect` helpers
 * remain re-exported because the omp-setup agent (which now owns binary
 * detection) reuses them via the setup-side tools.
 */

export {
  loadChallengeFolder,
  type LoadChallengeFolderOptions,
  type LoadChallengeFolderResult,
} from "./load-challenge-folder"
export {
  ChallengeLoadError,
  type ChallengeLoadErrorKind,
  type ChallengeLoadErrorDetail,
  type MissingDirDetail,
  type NotADirectoryDetail,
} from "./challenge-load-error"
export {
  detectBinary,
  isElf,
  isExecutable,
  looksLikeSharedObject,
  type DetectBinaryResult,
} from "./binary-detect"
