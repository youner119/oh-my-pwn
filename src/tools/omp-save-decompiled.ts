/**
 * omp_save_decompiled — BN decompile 결과를 LLM 경유 없이 파일로 직접 저장.
 *
 * 문제: Reverser가 decompile 결과를 write tool로 저장할 때,
 * pseudocode가 LLM 출력을 경유하면서 `...` 등으로 축약될 수 있음.
 *
 * 해결: 이 tool이 직접 BN plugin HTTP API에 연결 → decompile 호출 →
 * 결과를 파일에 직접 기록. LLM은 반환된 pseudocode를 분석용으로만 사용.
 *
 * 출력 경로: <challenge_dir>/.omp/artifacts/pseudocode/<filename>.txt
 */

import { mkdirSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"

export const ompSaveDecompiledTool: ToolDefinition = tool({
  description:
    "Save a function's complete decompiled HLIL pseudocode to disk WITHOUT " +
    "LLM intermediation. Calls the Binary Ninja HTTP API directly, and " +
    "writes the FULL result to <challenge_dir>/.omp/artifacts/pseudocode/" +
    "<filename>.txt. Returns the pseudocode in the response so you can use " +
    "it for analysis (purpose paragraphs, stack frame, key annotations) " +
    "without a separate decompile call. Provide function_name OR " +
    "function_address (name preferred after renaming). " +
    "Requires: BN GUI running with MCP plugin active (port 9009).",
  args: {
    challenge_dir: tool.schema
      .string()
      .describe("Absolute path to the challenge directory (parent of .omp/)"),
    function_name: tool.schema
      .string()
      .optional()
      .describe(
        "Function name to decompile (e.g. 'check_format_string'). " +
          "Preferred after renaming — avoids stale address references.",
      ),
    function_address: tool.schema
      .string()
      .optional()
      .describe(
        "Hex address of the function to decompile (e.g. '0x401209'). " +
          "Used when name is not available.",
      ),
    filename: tool.schema
      .string()
      .describe(
        "Output filename without extension (e.g. 'check_format_string'). " +
          "Will be saved as pseudocode/<filename>.txt",
      ),
  },
  execute: async ({ challenge_dir, function_name, function_address, filename }) => {
    if (!function_name && !function_address) {
      return JSON.stringify({
        error: "missing_identifier",
        message: "Provide function_name or function_address (or both).",
      })
    }

    // Sanitize filename: strip .txt if provided, remove path separators.
    const safeName = filename
      .replace(/\.txt$/u, "")
      .replace(/[/\\]/gu, "_")
    const outDir = join(challenge_dir, ".omp", "artifacts", "pseudocode")
    const outPath = join(outDir, `${safeName}.txt`)

    const bnPort = process.env["OMP_BN_PORT"] || "9009"
    const baseUrl = `http://localhost:${bnPort}`

    // Build query: prefer name, fall back to address.
    const query = function_name
      ? `name=${encodeURIComponent(function_name)}`
      : `address=${encodeURIComponent(function_address!)}`

    // Call BN plugin HTTP API directly — no MCP, no LLM intermediation.
    let resp: Response
    try {
      resp = await fetch(`${baseUrl}/decompile?${query}`, {
        signal: AbortSignal.timeout(45_000),
      })
    } catch (err) {
      return JSON.stringify({
        error: "connection_failed",
        message: `BN HTTP API 연결 실패 (${baseUrl}): ${String(err)}`,
      })
    }

    let json: Record<string, unknown>
    try {
      json = (await resp.json()) as Record<string, unknown>
    } catch {
      return JSON.stringify({
        error: "parse_failed",
        message: "BN decompile response is not valid JSON",
      })
    }

    if (json.error) {
      return JSON.stringify({
        error: "decompile_failed",
        message: `decompile failed for ${function_name ?? function_address}: ${String(json.error)}`,
        function_name,
        function_address,
      })
    }

    const code = json.decompiled as string | undefined
    if (!code || !code.trim()) {
      return JSON.stringify({
        error: "empty_result",
        message: `decompile returned empty for ${function_name ?? function_address}`,
        function_name,
        function_address,
      })
    }

    // Direct file write — no LLM output involved.
    mkdirSync(outDir, { recursive: true })
    writeFileSync(outPath, code, "utf-8")

    const lineCount = code.split("\n").length
    return JSON.stringify({
      ok: true,
      path: outPath,
      pseudocode_dir: outDir,
      lines: lineCount,
      function_name,
      function_address,
      code,
    })
  },
})
