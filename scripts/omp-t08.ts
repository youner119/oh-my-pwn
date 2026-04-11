#!/usr/bin/env bun
/**
 * Manual T08 driver — connect to ghidra-mcp (GUI mode), run a deterministic
 * Reverser analysis, and write the results for user verification.
 *
 * Usage:
 *   1. Open the binary in Ghidra GUI
 *   2. Start ghidra-mcp server: Tools > GhidraMCP > Start MCP Server (port 8089)
 *   3. Run this script:
 *
 *   bun scripts/omp-t08.ts <challenge-dir> [--port 8089]
 *
 * What it does:
 *   1. Loads existing ChallengeState (T03+T04 must have run already).
 *   2. Connects to ghidra-mcp GUI server via SSE.
 *   3. Lists functions, imports, exports, strings via MCP tools.
 *   4. Identifies key functions (entry -> main -> callees, skip externals).
 *   5. Decompiles key functions.
 *   6. Builds ReverserAnalysis and writes to .omp/artifacts/reverser-analysis.json.
 *   7. Updates state.json and appends to journal.
 *   8. Prints summary for user to verify against manual reversing.
 *
 * This exercises the full T06 ghidra-mcp infrastructure + T07 output format.
 */

import { existsSync, mkdirSync, writeFileSync } from "node:fs"
import { resolve, join } from "node:path"
import {
  loadChallengeState,
  saveChallengeState,
  appendJournalSection,
  resolveArtifactsDir,
  GhidraBridgeError,
  createGhidraMcpClient,
  checkGhidraHealth,
  listGhidraTools,
  getGhidraMetadata,
  buildGuiMcpConfig,
  DANGEROUS_FUNCTIONS,
  DANGEROUS_FUNCTION_REASONS,
  type GhidraFunction,
  type GhidraDecompilation,
  type GhidraImport,
  type GhidraExport,
  type DangerousCallEntry,
  type ReverserAnalysis,
  type McpToolCallResult,
} from "../src/features/omp"

// ---------------------------------------------------------------------------
// CLI parsing
// ---------------------------------------------------------------------------

interface CliArgs {
  challengeDir: string
}

function parseArgs(argv: readonly string[]): CliArgs {
  const args = [...argv]
  let challengeDir: string | undefined

  while (args.length > 0) {
    const next = args.shift()!
    if (next === "-h" || next === "--help") {
      printUsage()
      process.exit(0)
    }
    if (!challengeDir) {
      challengeDir = next
    }
  }

  if (!challengeDir) {
    printUsage()
    process.exit(1)
  }

  return { challengeDir: resolve(challengeDir) }
}

function printUsage(): void {
  console.log(`
Usage: bun scripts/omp-t08.ts <challenge-dir>

Prerequisites:
  1. T03+T04 must have run (run omp-t05.ts first if not done)
  2. Open the binary in Ghidra GUI (port 8089 REST API must be running)
     bridge_mcp_ghidra.py is spawned automatically as a stdio subprocess.
     Override bridge path: export OMP_GHIDRA_BRIDGE_PATH=/path/to/bridge_mcp_ghidra.py
`)
}

function die(msg: string): never {
  console.error(`\n  ERROR: ${msg}\n`)
  process.exit(1)
}

// ---------------------------------------------------------------------------
// MCP tool call helpers
// ---------------------------------------------------------------------------

function extractText(result: McpToolCallResult): string {
  return result.content
    .filter((b) => b.type === "text" && typeof b.text === "string")
    .map((b) => b.text as string)
    .join("")
}

function tryParseJson<T>(text: string): T | null {
  try {
    return JSON.parse(text) as T
  } catch {
    return null
  }
}

/**
 * Normalise a parsed JSON value into an array.
 *
 * ghidra-mcp tools may return either a bare array or an object whose first
 * array-valued property is the list we want (e.g. `{ "functions": [...] }`).
 */
function toArray(value: unknown): unknown[] {
  if (Array.isArray(value)) return value
  if (value !== null && typeof value === "object") {
    const first = Object.values(value as Record<string, unknown>).find(Array.isArray)
    if (first !== undefined) return first as unknown[]
  }
  return []
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const { challengeDir } = parseArgs(process.argv.slice(2))

  // ── 1. Load existing state ──────────────────────────────────────────────
  console.log(`\n  challenge dir : ${challengeDir}`)

  if (!existsSync(challengeDir)) {
    die(`Challenge directory does not exist: ${challengeDir}`)
  }

  const state = loadChallengeState(challengeDir)
  if (!state) {
    die("No .omp/state.json found. Run omp-t05.ts first (T03+T04).")
  }

  console.log(`  binary        : ${state.binary_path}`)
  console.log(`  libc          : ${state.libc_version ?? "unknown"}`)
  console.log(`  source present: ${state.source_present}`)

  // ── 2. Connect to ghidra-mcp via bridge (stdio) ─────────────────────────
  // bridge_mcp_ghidra.py is spawned as a subprocess and auto-connects to the
  // Ghidra GUI REST API on port 8089.
  const bridgePath =
    process.env.OMP_GHIDRA_BRIDGE_PATH ??
    `${process.env.HOME ?? "/home/youner119"}/Tools/ghidra_12.0.3_PUBLIC/bridge_mcp_ghidra.py`
  console.log(`\n  Spawning bridge: ${bridgePath}`)

  const client = createGhidraMcpClient()
  try {
    await client.connect(buildGuiMcpConfig())
  } catch (err) {
    if (err instanceof GhidraBridgeError) {
      die(
        `Connection failed (${err.kind}): ${err.message}\n\n` +
          `  Make sure:\n` +
          `    1. Ghidra GUI is open with the binary loaded\n` +
          `    2. Ghidra REST API is running on port 8089 (Tools > GhidraMCP > Start server)\n` +
          `    3. bridge_mcp_ghidra.py exists at: ${bridgePath}\n` +
          `       (override with OMP_GHIDRA_BRIDGE_PATH env var)`,
      )
    }
    throw err
  }

  const healthy = await checkGhidraHealth(client)
  if (healthy) {
    console.log("  Connected! Health check passed.")
  } else {
    // check_connection may fail for various bridge/version reasons even when
    // connected (e.g. the tool is not listed in the schema but still callable).
    // We fall through here and let step 3's listGhidraTools confirm liveness.
    console.log("  WARNING: check_connection returned unhealthy — will verify via tool listing.")
  }

  // ── 3. Server info + auto-import if no program loaded ──────────────────
  let metadata = await getGhidraMetadata(client)
  const programLoaded = metadata !== null && typeof metadata.programName === "string" && metadata.programName !== ""

  if (!programLoaded) {
    // No binary is open in Ghidra — import it automatically via import_file.
    console.log(`  No program loaded in Ghidra. Importing binary: ${state.binary_path}`)
    try {
      const importResult = await client.callTool("import_file", {
        file_path: state.binary_path,
      })
      const importText = extractText(importResult)
      // Some ghidra-mcp tools return {"error":"..."} without setting isError.
      const importJson = tryParseJson<Record<string, unknown>>(importText)
      const importError = importResult.isError ||
        (importJson !== null && typeof importJson.error === "string")
      if (importError) {
        die(
          `import_file failed: ${importText}\n\n` +
          `  Ensure Ghidra has a project open (File > New Project or File > Open Project).\n` +
          `  OMP_GHIDRA_PROJECT_PATH can point to a pre-created project dir.`,
        )
      }
      console.log(`  import_file: ${importText.slice(0, 200)}`)
      console.log("  Binary imported. Waiting for analysis...")
      // Re-fetch metadata after import.
      metadata = await getGhidraMetadata(client)
    } catch (err) {
      die(`Failed to import binary into Ghidra: ${String(err)}`)
    }
  }

  if (metadata) {
    console.log(`  program       : ${metadata.programName ?? "unknown"}`)
    console.log(`  language      : ${metadata.languageId ?? "unknown"}`)
    console.log(`  format        : ${metadata.executableFormat ?? "unknown"}`)
  }

  const tools = await listGhidraTools(client)
  if (!healthy && tools.length === 0) {
    die("Health check failed and no tools available. Is a program loaded in Ghidra?")
  }
  console.log(`  tools available: ${tools.length}`)

  // ── 4. List functions ───────────────────────────────────────────────────
  console.log("\n  Listing functions...")
  let functionsResult: McpToolCallResult
  try {
    functionsResult = await client.callTool("list_functions_enhanced", { limit: 500 })
  } catch {
    functionsResult = await client.callTool("list_functions", { limit: 500 })
  }
  const functionsText = extractText(functionsResult)
  const rawFunctions = toArray(tryParseJson<unknown>(functionsText))
  const functions: GhidraFunction[] = rawFunctions
    .filter((item): item is Record<string, unknown> => item !== null && typeof item === "object")
    .map((item) => ({
      name: String(item.name ?? ""),
      address: String(item.address ?? item.entry_point ?? "0x0"),
      size: typeof item.size === "number" ? item.size : undefined,
      isThunk: typeof item.is_thunk === "boolean" ? item.is_thunk : typeof item.isThunk === "boolean" ? item.isThunk : undefined,
      isExternal: typeof item.is_external === "boolean" ? item.is_external : typeof item.isExternal === "boolean" ? item.isExternal : undefined,
    }))
  console.log(`  total functions: ${functions.length}`)

  const userFunctions = functions.filter((f) => !f.isThunk && !f.isExternal)
  console.log(`  user functions : ${userFunctions.length}`)

  // ── 5. List imports ─────────────────────────────────────────────────────
  console.log("  Listing imports...")
  const importsResult = await client.callTool("list_imports", { limit: 500 })
  const rawImports = toArray(tryParseJson<unknown>(extractText(importsResult)))
  const imports: GhidraImport[] = rawImports
    .filter((item): item is Record<string, unknown> => item !== null && typeof item === "object")
    .map((item) => ({
      name: String(item.name ?? ""),
      library: typeof item.library === "string" ? item.library : undefined,
      address: typeof item.address === "string" ? item.address : undefined,
    }))
  console.log(`  imports        : ${imports.length}`)

  // ── 6. List exports ─────────────────────────────────────────────────────
  const exportsResult = await client.callTool("list_exports", { limit: 500 })
  const rawExports = toArray(tryParseJson<unknown>(extractText(exportsResult)))
  const exports: GhidraExport[] = rawExports
    .filter((item): item is Record<string, unknown> => item !== null && typeof item === "object")
    .map((item) => ({
      name: String(item.name ?? ""),
      address: String(item.address ?? "0x0"),
    }))

  // ── 7. Identify dangerous calls ─────────────────────────────────────────
  const dangerousImports = imports.filter((imp) => DANGEROUS_FUNCTIONS.has(imp.name))
  console.log(`  dangerous imports: ${dangerousImports.length} (${dangerousImports.map((i) => i.name).join(", ")})`)

  const dangerousCalls: DangerousCallEntry[] = []
  for (const imp of dangerousImports) {
    if (!imp.address) continue
    try {
      const xrefResult = await client.callTool("get_xrefs_to", { address: imp.address })
      const rawXrefs = tryParseJson<unknown[]>(extractText(xrefResult)) ?? []
      for (const xref of rawXrefs) {
        if (xref === null || typeof xref !== "object") continue
        const x = xref as Record<string, unknown>
        const refType = String(x.refType ?? x.ref_type ?? x.type ?? "")
        if (refType === "CALL" || refType === "COMPUTED_CALL") {
          dangerousCalls.push({
            callee: imp.name,
            caller: String(x.fromFunction ?? x.from_function ?? x.fromAddress ?? x.from_address ?? "unknown"),
            callerAddress: String(x.fromAddress ?? x.from_address ?? x.from ?? "0x0"),
            reason: DANGEROUS_FUNCTION_REASONS[imp.name] ?? "known-dangerous function",
          })
        }
      }
    } catch {
      // xref lookup failed — non-fatal
    }
  }
  console.log(`  dangerous call sites: ${dangerousCalls.length}`)

  // ── 8. Decompile key functions ──────────────────────────────────────────
  // Strategy: decompile all user-defined functions (up to 30).
  // In the real agent, AI selects which functions matter. Here we do all small ones.
  const toDecompile = state.source_present
    ? [] // source present → skip decompilation, only address mapping
    : userFunctions.slice(0, 30)

  console.log(`\n  Decompiling ${toDecompile.length} functions...`)
  const decompilations: Record<string, GhidraDecompilation> = {}

  for (const fn of toDecompile) {
    try {
      const result = await client.callTool("decompile_function", { function_address: fn.address })
      if (result.isError) continue
      const text = extractText(result).trim()
      if (!text) continue

      const parsed = tryParseJson<Record<string, unknown>>(text)
      const code = parsed
        ? String(parsed.code ?? parsed.decompiled ?? text)
        : text

      decompilations[fn.address] = {
        functionName: fn.name,
        address: fn.address,
        code,
      }
      console.log(`    ${fn.name} @ ${fn.address} — ${code.split("\n").length} lines`)
    } catch {
      console.log(`    ${fn.name} @ ${fn.address} — FAILED`)
    }
  }
  console.log(`  decompiled: ${Object.keys(decompilations).length}/${toDecompile.length}`)

  // ── 9. Build ReverserAnalysis + write to disk ───────────────────────────
  const analysis: ReverserAnalysis = {
    functions,
    decompilations,
    imports,
    exports,
    dangerousCalls,
    analyzedAt: new Date().toISOString(),
  }

  const artifactsDir = resolveArtifactsDir(challengeDir)
  if (!existsSync(artifactsDir)) {
    mkdirSync(artifactsDir, { recursive: true })
  }
  const analysisPath = join(artifactsDir, "reverser-analysis.json")
  writeFileSync(analysisPath, JSON.stringify(analysis, null, 2))
  console.log(`\n  Analysis written to: ${analysisPath}`)

  // ── 10. Update state ────────────────────────────────────────────────────
  const updatedState = saveChallengeState({
    ...state,
    reverser_summary_path: analysisPath,
    reverser_analyzed_at: new Date().toISOString(),
  })
  console.log("  state.json updated")

  // ── 11. Append journal ──────────────────────────────────────────────────
  const journalLines = [
    `**Functions:** ${functions.length} total, ${userFunctions.length} user-defined, ${Object.keys(decompilations).length} decompiled`,
    `**Imports:** ${imports.length} (dangerous: ${dangerousImports.map((i) => i.name).join(", ") || "none"})`,
    `**Dangerous call sites:** ${dangerousCalls.length}`,
    "",
    "### Key Functions",
    "",
    "| Name | Address | Decompiled | Notes |",
    "|------|---------|------------|-------|",
    ...userFunctions.slice(0, 30).map((fn) => {
      const dec = decompilations[fn.address]
      const calls = dangerousCalls.filter((dc) => dc.caller === fn.name || dc.callerAddress === fn.address)
      const notes = calls.length > 0 ? calls.map((c) => `calls ${c.callee}`).join(", ") : ""
      return `| ${fn.name} | ${fn.address} | ${dec ? "yes" : "no"} | ${notes} |`
    }),
    "",
    "### Dangerous Calls",
    "",
    ...(dangerousCalls.length > 0
      ? [
          "| Callee | Caller | Address | Reason |",
          "|--------|--------|---------|--------|",
          ...dangerousCalls.map((dc) => `| ${dc.callee} | ${dc.caller} | ${dc.callerAddress} | ${dc.reason} |`),
        ]
      : ["None detected."]),
    "",
    `Analysis file: \`${analysisPath}\``,
  ]

  appendJournalSection(challengeDir, "Reverser Analysis (T08 manual test)", journalLines.join("\n"))
  console.log("  journal updated")

  // ── 12. Summary ─────────────────────────────────────────────────────────
  console.log("\n" + "=".repeat(60))
  console.log("  T08 REVERSER TEST COMPLETE")
  console.log("=".repeat(60))
  console.log(`
  Verify these against your manual reversing:

  Functions     : ${functions.length} total / ${userFunctions.length} user-defined
  Decompiled    : ${Object.keys(decompilations).length}
  Imports       : ${imports.length}
  Dangerous calls: ${dangerousCalls.length}

  Files to inspect:
    analysis  : ${analysisPath}
    journal   : ${join(challengeDir, ".omp", "journal.md")}
    state     : ${join(challengeDir, ".omp", "state.json")}
  `)

  if (dangerousCalls.length > 0) {
    console.log("  Dangerous call summary:")
    for (const dc of dangerousCalls) {
      console.log(`    ${dc.callee}() called from ${dc.caller} @ ${dc.callerAddress} — ${dc.reason}`)
    }
    console.log()
  }

  // ── Cleanup ─────────────────────────────────────────────────────────────
  await client.disconnect()
  console.log("  Connection closed. Done.\n")
}

main().catch((err) => {
  if (err instanceof GhidraBridgeError) {
    console.error(`\n  GhidraBridgeError [${err.kind}]: ${err.message}`)
    console.error("  detail:", JSON.stringify(err.detail, null, 2))
  } else {
    console.error("\n  Unexpected error:", err)
  }
  process.exit(1)
})
