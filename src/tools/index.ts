export { ompReadStateTool } from "./omp-read-state"
export { ompPatchStateTool } from "./omp-patch-state"
export { ompAppendJournalTool } from "./omp-append-journal"
// Candidate per-file tools (spec: state-split-vuln-candidates.md P3).
export { ompReadCandidateTool } from "./omp-read-candidate"
export { ompCreateCandidateTool } from "./omp-create-candidate"
export { ompPatchCandidateTool } from "./omp-patch-candidate"
export { ompDeleteCandidateTool } from "./omp-delete-candidate"
export {
  createOmpLoadChallengeTool,
  ompLoadChallengeTool,
} from "./omp-load-challenge"
export type { OmpLoadChallengeToolOptions } from "./omp-load-challenge"
export { ompGetTemplateTool } from "./omp-get-template"
export { ompVerifyTemplateOutputTool } from "./omp-verify-template-output"
// omp_save_decompiled removed — BN MCP tool `decompile_to_file` replaces it.
// omp_run_envsetup / omp_stage_challenge / omp_pwno_status retired by
// T12-T14 — omp-setup agent absorbs all three.

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
