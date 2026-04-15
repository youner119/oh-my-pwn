/**
 * T06 — ghidra-mcp integration (barrel).
 *
 * Public surface for the ghidra-mcp integration. The OmP feature root
 * re-exports these from `src/features/omp/index.ts`.
 *
 * `fake-client.ts` is intentionally NOT exported here — it is test-only,
 * following the same convention as `fake-docker-runner.ts` in the envsetup
 * module.
 */

// types
export type {
  GhidraMcpConfig,
  GhidraMcpClient,
  GhidraFunction,
  GhidraDecompilation,
  GhidraString,
  GhidraImport,
  GhidraExport,
  GhidraXref,
  McpToolCallResult,
  McpContentBlock,
  McpToolInfo,
} from "./types"

// errors
export {
  GhidraBridgeError,
  type GhidraBridgeErrorKind,
  type GhidraBridgeErrorDetail,
} from "./errors"

// client
export { createGhidraMcpClient } from "./client"

// server lifecycle
export {
  launchGhidraServer,
  checkGhidraHealth,
  getGhidraMetadata,
  listGhidraTools,
  createDefaultGhidraConfig,
  type GhidraServerMetadata,
} from "./server"

// headless launcher
export {
  runHeadlessImport,
  resolveGhidraHome,
  resolveProjectPath,
  buildHeadlessMcpConfig,
  buildGuiMcpConfig,
  type HeadlessConfig,
  type HeadlessResult,
} from "./headless"

// connection manager
export {
  connectToGhidra,
  type GhidraConnectionOptions,
  type GhidraConnection,
} from "./connection"
