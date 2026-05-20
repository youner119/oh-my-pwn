/**
 * oh-my-pwn (OmP) — CTF pwnable auto-solve multi-agent harness.
 * Standalone project. Reference: oh-my-openagent patterns.
 */

// Agents
export { createOmpOrchestratorAgent } from "./agents/omp-orchestrator"
export { createOmpReverserAgent } from "./agents/omp-reverser"
export type { AgentConfig, AgentMode, AgentFactory } from "./agents/types"

// State (T02)
export {
  ChallengeStateSchema,
  createInitialChallengeState,
  type ChallengeState,
  type Mitigations,
  type RemoteEntrypoint,
  type VulnCandidate,
  type UserCorrection,
  type InitialChallengeStateInput,
} from "./state/challenge-state"
export {
  initializeOmpDir,
  loadChallengeState,
  saveChallengeState,
  getStatePaths,
  ChallengeStateLoadError,
} from "./state/io"
export {
  appendJournalSection,
  appendUserCorrection,
  initializeJournal,
} from "./state/journal"
export {
  resolveOmpDir,
  resolveStatePath,
  resolveJournalPath,
  resolveExploitDir,
  resolveLogsDir,
  resolveArtifactsDir,
  OMP_SUBDIRS,
} from "./state/layout"
export {
  OMP_DIR,
  STATE_FILE,
  JOURNAL_FILE,
  EXPLOIT_DIR,
  LOGS_DIR,
  ARTIFACTS_DIR,
  CHALLENGE_STATE_SCHEMA_VERSION,
} from "./state/constants"

// Loader (T03)
export {
  loadChallengeFolder,
  type LoadChallengeFolderOptions,
  type LoadChallengeFolderResult,
  ChallengeLoadError,
  type ChallengeLoadErrorKind,
  type ChallengeLoadErrorDetail,
  detectBinary,
  isElf,
  isExecutable,
  looksLikeSharedObject,
} from "./loader"

// EnvSetup helpers (post-T19) — surface trimmed to what the omp-setup
// agent's atomic tools still need. Legacy `runEnvSetup` + sub-helpers
// (dockerfile parser, ELF mitigations, glibc detect, docker-extract,
// patchelf) were removed in T19; the omp-setup agent does those via bash
// + the typed atomic tools now.
export {
  EnvSetupError,
  type EnvSetupErrorKind,
  type EnvSetupErrorDetail,
  realDockerRunner,
  type DockerRunner,
  type DockerRunResult,
  type DockerRunOptions,
  dockerBuildImage,
  type DockerBuildResult,
  type DockerBuildOptions,
} from "./envsetup"

// Ghidra-MCP (T06) — removed in feat/binary-ninja branch.
// BN MCP is handled by opencode via stdio bridge; no custom client needed.
