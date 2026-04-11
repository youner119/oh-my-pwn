/**
 * T03 — challenge folder loader & validator (barrel).
 *
 * Public surface for the loader. The OmP feature root re-exports these from
 * `src/features/omp/index.ts` so call sites import them as
 * `import { loadChallengeFolder } from "<feature-root>"` rather than reaching
 * into this subdirectory directly.
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
  type AmbiguousBinaryDetail,
  type MissingBinaryDetail,
  type BinaryNotElfDetail,
  type BinaryNotExecutableDetail,
  type MissingDirDetail,
  type NotADirectoryDetail,
  type MissingDockerfileDetail,
} from "./challenge-load-error"
export {
  detectBinary,
  isElf,
  isExecutable,
  looksLikeSharedObject,
} from "./binary-detect"
