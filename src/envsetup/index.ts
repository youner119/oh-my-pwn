/**
 * EnvSetup library — public surface for the deterministic build helpers
 * that the omp-setup agent's atomic tools (`omp_setup_docker_build`,
 * `omp_setup_extract_file`, `omp_setup_patch_elf`, `omp_setup_verify_runtime`)
 * rely on.
 *
 * The legacy `runEnvSetup` orchestrator and its sub-helpers (dockerfile
 * parser, ELF mitigations, glibc detect, docker-extract, in-place
 * `patchBinaryInterpreter`) were retired with T19. The omp-setup agent
 * performs those steps itself via bash inspection + the typed atomic
 * tools, so the library no longer carries them.
 */

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
  dockerBuildImage,
  type DockerBuildResult,
  type DockerBuildOptions,
} from "./docker-build"

export {
  patchElf,
  type PatchElfInputs,
  type PatchElfResult,
  type PatchelfOptions,
  type SpawnFn,
  type SpawnResult,
} from "./patch-elf"
