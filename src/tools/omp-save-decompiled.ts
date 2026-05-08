/**
 * omp_save_decompiled — Ghidra decompile 결과를 LLM 경유 없이 파일로 직접 저장.
 *
 * 문제: Reverser가 decompile_function 결과를 write tool로 저장할 때,
 * pseudocode가 LLM 출력을 경유하면서 `...` 등으로 축약될 수 있음.
 *
 * 해결: 이 tool이 직접 Ghidra HTTP API에 연결 → decompile_function 호출 →
 * 결과를 파일에 직접 기록. LLM은 반환된 pseudocode를 분석용으로만 사용.
 *
 * 출력 경로: <challenge_dir>/.omp/artifacts/pseudocode/<filename>.txt
 */

import { mkdirSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"

export const ompSaveDecompiledTool: ToolDefinition = tool({
  description:
    "Save a function's complete decompiled pseudocode to disk WITHOUT LLM " +
    "intermediation. Calls the Ghidra HTTP API directly, and writes the FULL " +
    "result to <challenge_dir>/.omp/artifacts/pseudocode/<filename>.txt. " +
    "Returns the pseudocode in the response so you can use it for analysis " +
    "(purpose paragraphs, stack frame, key annotations) without a separate " +
    "decompile_function call. " +
    "Requires: Ghidra GUI running with the target binary open (Reverser step 0 must be done first).",
  args: {
    challenge_dir: tool.schema
      .string()
      .describe("Absolute path to the challenge directory (parent of .omp/)"),
    function_address: tool.schema
      .string()
      .describe(
        "Hex address of the function to decompile (e.g. '0x00152700')",
      ),
    filename: tool.schema
      .string()
      .describe(
        "Output filename without extension (e.g. 'run_bof_loop'). " +
          "Will be saved as pseudocode/<filename>.txt",
      ),
  },
  execute: async ({ challenge_dir, function_address, filename }) => {
    // Sanitize filename: strip .txt if provided, remove path separators.
    const safeName = filename
      .replace(/\.txt$/u, "")
      .replace(/[/\\]/gu, "_")
    const outDir = join(challenge_dir, ".omp", "artifacts", "pseudocode")
    const outPath = join(outDir, `${safeName}.txt`)

    const guiPort = process.env["OMP_GHIDRA_GUI_PORT"] || "8089"
    const baseUrl = `http://localhost:${guiPort}`

    // Call Ghidra HTTP API directly — no MCP, no LLM intermediation.
    let resp: Response
    try {
      resp = await fetch(
        `${baseUrl}/decompile_function?address=${encodeURIComponent(function_address)}`,
        { signal: AbortSignal.timeout(45_000) },
      )
    } catch (err) {
      return JSON.stringify({
        error: "connection_failed",
        message: `Ghidra HTTP API 연결 실패 (${baseUrl}): ${String(err)}`,
      })
    }

    const body = await resp.text()

    // Ghidra returns JSON with { error: "..." } on failure.
    if (!resp.ok || body.startsWith('{"error"')) {
      return JSON.stringify({
        error: "decompile_failed",
        message: `decompile_function failed for ${function_address}: ${body}`,
        function_address,
      })
    }

    if (!body.trim()) {
      return JSON.stringify({
        error: "empty_result",
        message: `decompile_function returned empty for ${function_address}`,
        function_address,
      })
    }

    // Direct file write — no LLM output involved.
    mkdirSync(outDir, { recursive: true })
    writeFileSync(outPath, body, "utf-8")

    const lineCount = body.split("\n").length
    return JSON.stringify({
      ok: true,
      path: outPath,
      pseudocode_dir: outDir,
      lines: lineCount,
      function_address,
      code: body,
    })
  },
})
