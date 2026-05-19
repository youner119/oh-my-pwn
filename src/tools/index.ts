export { ompReadStateTool } from "./omp-read-state"
export { ompPatchStateTool } from "./omp-patch-state"
export { ompAppendJournalTool } from "./omp-append-journal"
export { ompRunEnvsetupTool } from "./omp-run-envsetup"
export {
  createOmpLoadChallengeTool,
  ompLoadChallengeTool,
} from "./omp-load-challenge"
export type { OmpLoadChallengeToolOptions } from "./omp-load-challenge"
export { ompGetTemplateTool } from "./omp-get-template"
export { ompVerifyTemplateOutputTool } from "./omp-verify-template-output"
export { createOmpStageChallengeTool } from "./stage-challenge"
export type { StageChallengeToolOptions } from "./stage-challenge"
// omp_save_decompiled removed — BN MCP tool `decompile_to_file` replaces it.

// omp-setup agent atomic tools (T02 skeletons; T04/T06/T07/T08 implementations).
// Spec: `.omc/specs/deep-interview-envsetup-agent.md`.
// inspect_folder / probe_image were considered but deferred — Phase 0 is
// fully agentic (bash inspection) so deterministic tools are not needed.
export { createOmpSetupDockerBuildTool } from "./omp-setup-docker-build"
export type { OmpSetupDockerBuildToolOptions } from "./omp-setup-docker-build"
export { createOmpSetupExtractFileTool } from "./omp-setup-extract-file"
export type { OmpSetupExtractFileToolOptions } from "./omp-setup-extract-file"
export { createOmpSetupPatchElfTool } from "./omp-setup-patch-elf"
export type { OmpSetupPatchElfToolOptions } from "./omp-setup-patch-elf"
export { createOmpSetupVerifyRuntimeTool } from "./omp-setup-verify-runtime"
export type { OmpSetupVerifyRuntimeToolOptions } from "./omp-setup-verify-runtime"
