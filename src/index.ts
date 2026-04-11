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
  type LeakEntry,
  type VulnCandidate,
  type StageEntry,
  type StageStatus,
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

// EnvSetup (T04)
export {
  runEnvSetup,
  type RunEnvSetupOptions,
  type RunEnvSetupResult,
  EnvSetupError,
  type EnvSetupErrorKind,
  type EnvSetupErrorDetail,
  realDockerRunner,
  type DockerRunner,
  type DockerRunResult,
  type DockerRunOptions,
  parseDockerfile,
  parseDockerfileText,
  type ParsedDockerfile,
  parseElfMitigations,
  hasInterpSegment,
  ElfParseError,
  type ElfMitigations,
  detectGlibcVersion,
  detectGlibcVersionFromBytes,
  dockerBuildImage,
  type DockerBuildResult,
  type DockerBuildOptions,
  extractLibcAndLd,
  type DockerExtractResult,
  type DockerExtractDynamicResult,
  type DockerExtractStaticResult,
  type DockerExtractInputs,
  patchBinaryInterpreter,
  type PatchelfInputs,
  type PatchelfOptions,
  type PatchelfResult,
  type SpawnFn,
  type SpawnResult,
} from "./envsetup"

// Ghidra-MCP (T06)
export {
  createGhidraMcpClient,
  launchGhidraServer,
  checkGhidraHealth,
  getGhidraMetadata,
  listGhidraTools,
  createDefaultGhidraConfig,
  DANGEROUS_FUNCTION_REASONS,
  DANGEROUS_FUNCTIONS,
  formatDangerousFunctionsForPrompt,
  runHeadlessImport,
  resolveGhidraHome,
  resolveProjectPath,
  buildHeadlessMcpConfig,
  buildGuiMcpConfig,
  type HeadlessConfig,
  type HeadlessResult,
  connectToGhidra,
  type GhidraConnectionOptions,
  type GhidraConnection,
  type GhidraMcpConfig,
  type GhidraMcpClient,
  type GhidraFunction,
  type GhidraDecompilation,
  type GhidraString,
  type GhidraImport,
  type GhidraExport,
  type GhidraXref,
  type GhidraStructuralSummary,
  type DangerousCallEntry,
  type McpToolCallResult,
  type McpContentBlock,
  type McpToolInfo,
  type ReverserAnalysis,
  type GhidraServerMetadata,
  GhidraBridgeError,
  type GhidraBridgeErrorKind,
  type GhidraBridgeErrorDetail,
} from "./ghidra"
