/**
 * Ghidra headless launcher for OmP.
 *
 * Runs `analyzeHeadless` to import + analyze a binary into a shared Ghidra
 * project, then provides a {@link GhidraMcpConfig} that the connection layer
 * can use to launch `bridge_mcp_ghidra.py` via stdio transport.
 *
 * DI seam: the `spawn` field in {@link HeadlessConfig} accepts a
 * {@link SpawnFn} for unit tests. The default implementation uses
 * `spawnSync` from `node:child_process`.
 */

import { spawnSync } from "node:child_process"
import { mkdirSync } from "node:fs"
import path from "node:path"
import { GhidraBridgeError } from "./errors.js"
import type { GhidraMcpConfig } from "./types.js"

// ---------------------------------------------------------------------------
// DI seam types (self-contained to avoid circular imports with envsetup)
// ---------------------------------------------------------------------------

/** Result returned by a spawned subprocess. */
export interface SpawnResult {
  exitCode: number
  stdout: Buffer
  stderr: Buffer
}

/**
 * Minimal subprocess abstraction used for DI in tests.
 *
 * The real implementation wraps `spawnSync`. Tests inject a function that
 * returns canned data or throws a simulated spawn error.
 */
export type SpawnFn = (
  cmd: string,
  args: string[],
  opts?: { cwd?: string; timeout?: number },
) => SpawnResult

// ---------------------------------------------------------------------------
// Config + result types
// ---------------------------------------------------------------------------

/** Configuration for the Ghidra headless launcher. */
export interface HeadlessConfig {
  /**
   * Path to GHIDRA_HOME (e.g. "/opt/ghidra").
   * Falls back to `process.env.GHIDRA_HOME` when not set.
   */
  ghidraHome?: string
  /**
   * Path to the shared Ghidra project directory.
   * Falls back to `process.env.OMP_GHIDRA_PROJECT_PATH` or the default path.
   */
  projectPath?: string
  /**
   * Project name within the project directory.
   * Defaults to `"omp-" + path.basename(binaryPath)`.
   */
  projectName?: string
  /** Timeout for headless analysis in ms. Default: 120_000. */
  analysisTimeoutMs?: number
  /** Inject a fake spawn function for tests. Defaults to `spawnSync`. */
  spawn?: SpawnFn
}

/** Result of a successful headless import. */
export interface HeadlessResult {
  /** The project path used. */
  projectPath: string
  /** The project name used. */
  projectName: string
  /** Whether the binary was freshly imported (vs already in project). */
  freshImport: boolean
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_PROJECT_PATH = "/mnt/D/Hack/omp_ghidra_project"
const DEFAULT_BRIDGE_PATH = `${process.env.HOME ?? "/home/youner119"}/Tools/ghidra_12.0.3_PUBLIC/bridge_mcp_ghidra.py`
const DEFAULT_ANALYSIS_TIMEOUT_MS = 120_000

// ---------------------------------------------------------------------------
// Real spawn implementation
// ---------------------------------------------------------------------------

const realSpawn: SpawnFn = (cmd, args, opts = {}) => {
  const result = spawnSync(cmd, args, {
    cwd: opts.cwd,
    timeout: opts.timeout,
  })
  if (result.error !== undefined && result.error !== null) {
    throw result.error
  }
  return {
    exitCode: result.status ?? -1,
    stdout: result.stdout ?? Buffer.alloc(0),
    stderr: result.stderr ?? Buffer.alloc(0),
  }
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/**
 * Resolve the Ghidra installation directory.
 *
 * Priority: `config.ghidraHome` > `process.env.GHIDRA_HOME`.
 *
 * @throws {@link GhidraBridgeError} with kind `"not-configured"` when neither
 *   source is set.
 */
export function resolveGhidraHome(config?: HeadlessConfig): string {
  const home = config?.ghidraHome ?? process.env.GHIDRA_HOME
  if (home === undefined || home === "") {
    throw new GhidraBridgeError({
      kind: "not-configured",
      field: "GHIDRA_HOME",
      message:
        "GHIDRA_HOME is not set. Set process.env.GHIDRA_HOME or pass ghidraHome in HeadlessConfig.",
    })
  }
  return home
}

/**
 * Resolve the shared Ghidra project directory path.
 *
 * Priority: `config.projectPath` > `process.env.OMP_GHIDRA_PROJECT_PATH` >
 * default (`/mnt/D/Hack/omp_ghidra_project`).
 */
export function resolveProjectPath(config?: HeadlessConfig): string {
  return (
    config?.projectPath ??
    process.env.OMP_GHIDRA_PROJECT_PATH ??
    DEFAULT_PROJECT_PATH
  )
}

/**
 * Run `analyzeHeadless` to import and analyze a binary into the shared
 * Ghidra project.
 *
 * Steps:
 *   1. Resolve ghidraHome and projectPath.
 *   2. Ensure the project directory exists (creates recursively if missing).
 *   3. Invoke `{ghidraHome}/support/analyzeHeadless {projectPath} {projectName}
 *      -import {binaryPath} -overwrite`.
 *   4. Translate spawn-level failures (`ENOENT`) and non-zero exit codes into
 *      typed {@link GhidraBridgeError} instances.
 *
 * @param binaryPath - Absolute path to the challenge binary to import.
 * @param config - Optional configuration overrides and DI seam.
 * @returns {@link HeadlessResult} describing the completed import.
 *
 * @throws {@link GhidraBridgeError} with kind `"not-configured"` when
 *   `analyzeHeadless` cannot be found.
 * @throws {@link GhidraBridgeError} with kind `"server-error"` when
 *   `analyzeHeadless` exits with a non-zero code.
 */
export function runHeadlessImport(
  binaryPath: string,
  config?: HeadlessConfig,
): HeadlessResult {
  const ghidraHome = resolveGhidraHome(config)
  const projectPath = resolveProjectPath(config)
  const projectName =
    config?.projectName ?? `omp-${path.basename(binaryPath)}`
  const timeoutMs = config?.analysisTimeoutMs ?? DEFAULT_ANALYSIS_TIMEOUT_MS
  const spawn = config?.spawn ?? realSpawn

  // Ensure the project directory exists before invoking analyzeHeadless.
  mkdirSync(projectPath, { recursive: true })

  const analyzeHeadless = path.join(ghidraHome, "support", "analyzeHeadless")
  const args = [projectPath, projectName, "-import", binaryPath, "-overwrite"]

  let result: SpawnResult
  try {
    result = spawn(analyzeHeadless, args, { timeout: timeoutMs })
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code
    if (code === "ENOENT") {
      throw new GhidraBridgeError({
        kind: "not-configured",
        field: "GHIDRA_HOME",
        message: `analyzeHeadless not found at ${analyzeHeadless}. Verify GHIDRA_HOME points to a valid Ghidra installation.`,
      })
    }
    throw new GhidraBridgeError({
      kind: "server-error",
      message: `Failed to spawn analyzeHeadless: ${(err as Error).message}`,
    })
  }

  if (result.exitCode !== 0) {
    const stderrText = result.stderr.toString("utf-8")
    throw new GhidraBridgeError({
      kind: "server-error",
      serverError: truncate(stderrText, 1024),
      message:
        `analyzeHeadless exited with code ${result.exitCode}. ` +
        `stderr: ${truncate(stderrText, 200)}`,
    })
  }

  return {
    projectPath,
    projectName,
    freshImport: true,
  }
}

/**
 * Build a {@link GhidraMcpConfig} for the stdio-transport MCP server
 * (`bridge_mcp_ghidra.py`).
 *
 * This config is passed to `connection.ts` after a successful headless import
 * so the bridge can connect to Ghidra's RMI backend via the Python script.
 */
export function buildHeadlessMcpConfig(_config?: HeadlessConfig): GhidraMcpConfig {
  const bridgePath =
    process.env.OMP_GHIDRA_BRIDGE_PATH ?? DEFAULT_BRIDGE_PATH
  return {
    type: "stdio",
    command: "python3",
    args: [bridgePath],
    timeoutMs: 60_000,
  }
}

/**
 * Build a {@link GhidraMcpConfig} for connecting to an already-running bridge
 * (GUI mode) via stdio — spawns `bridge_mcp_ghidra.py` which auto-connects
 * to the Ghidra GUI on port 8089.
 */
export function buildGuiMcpConfig(): GhidraMcpConfig {
  const bridgePath =
    process.env.OMP_GHIDRA_BRIDGE_PATH ?? DEFAULT_BRIDGE_PATH
  return {
    type: "stdio",
    command: "python3",
    args: [bridgePath],
    timeoutMs: 30_000,
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function truncate(text: string, max: number): string {
  if (text.length <= max) {
    return text
  }
  return `${text.slice(0, max)}\n... (truncated, ${text.length - max} more bytes)`
}
