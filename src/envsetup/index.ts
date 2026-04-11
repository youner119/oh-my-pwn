/**
 * T04 — EnvSetup library (barrel).
 *
 * Public surface for the deterministic EnvSetup pipeline. The OmP feature
 * root re-exports these from `src/features/omp/index.ts`.
 *
 * The barrel exports BOTH the high-level `runEnvSetup` entry point AND
 * every low-level building block. The low-level exports are deliberate:
 * per the T04 pre-work decision a future LLM-agent wrapper should be able
 * to call individual steps (`parseDockerfile`, `parseElfMitigations`,
 * `dockerBuildImage`, `extractLibcAndLd`, `detectGlibcVersion`) without
 * being forced through `runEnvSetup`.
 */

export {
  runEnvSetup,
  type RunEnvSetupOptions,
  type RunEnvSetupResult,
} from "./run-envsetup"

export {
  EnvSetupError,
  type EnvSetupErrorKind,
  type EnvSetupErrorDetail,
  type StateMissingDetail,
  type DockerNotAvailableDetail,
  type DockerBuildFailedDetail,
  type ElfParseErrorDetail,
  type ExtractionFailedDetail,
  type LibcNotFoundDetail,
  type PatchelfNotAvailableDetail,
  type PatchelfFailedDetail,
} from "./envsetup-error"

export {
  realDockerRunner,
  type DockerRunner,
  type DockerRunResult,
  type DockerRunOptions,
} from "./docker-runner"

export {
  parseDockerfile,
  parseDockerfileText,
  type ParsedDockerfile,
} from "./dockerfile-parse"

export {
  parseElfMitigations,
  hasInterpSegment,
  ElfParseError,
  type ElfMitigations,
} from "./elf-mitigations"

export {
  detectGlibcVersion,
  detectGlibcVersionFromBytes,
} from "./glibc-detect"

export {
  dockerBuildImage,
  type DockerBuildResult,
  type DockerBuildOptions,
} from "./docker-build"

export {
  extractLibcAndLd,
  type DockerExtractResult,
  type DockerExtractDynamicResult,
  type DockerExtractStaticResult,
  type DockerExtractInputs,
} from "./docker-extract"

export {
  patchBinaryInterpreter,
  type PatchelfInputs,
  type PatchelfOptions,
  type PatchelfResult,
  type SpawnFn,
  type SpawnResult,
} from "./patch-elf"
