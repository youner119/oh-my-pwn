/**
 * omp-db MCP server entry point.
 *
 * Spec: `.omc/specs/deep-interview-database-mcp.md` (T4).
 *
 * Launched by opencode as a stdio MCP process from `opencode.json`'s
 * `mcp.omp-db` entry:
 *
 *   { "command": ["bun", "<repo>/dist/db-mcp.js"],
 *     "environment": { "OMP_DB_PATH": "<repo>/state.db" } }
 *
 * The DB path comes from `OMP_DB_PATH` (locked decision 2026-06-05) — explicit,
 * test-overridable, parallels how pwno-mcp receives its mounts. Missing env =
 * fail fast (the server cannot guess the global DB location).
 *
 * stdout is the JSON-RPC channel — all diagnostics go to stderr.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"

import { openDb } from "../db"
import { createDbMcpServer } from "./server"

async function main(): Promise<void> {
  const dbPath = process.env["OMP_DB_PATH"]
  if (!dbPath) {
    console.error(
      "[omp-db] FATAL: OMP_DB_PATH is not set. The opencode.json mcp.omp-db " +
        "entry must inject the absolute path to the global state.db.",
    )
    process.exit(1)
  }

  // Eager open — apply pragmas (WAL + foreign_keys) and run migrations so the
  // server fails loudly at startup rather than on the first tool call.
  const db = openDb({ dbPath })
  const server = createDbMcpServer(db)

  const transport = new StdioServerTransport()
  await server.connect(transport)
  console.error(`[omp-db] connected (db=${dbPath})`)
}

main().catch((err) => {
  console.error("[omp-db] FATAL:", err)
  process.exit(1)
})
