/**
 * omp_append_journal — journal.md append tool.
 *
 * 에이전트가 작업 결과를 journal에 기록할 때 사용.
 * journal.md는 append-only이므로 기존 내용을 덮어쓰지 않음.
 * 타임스탬프는 서버사이드에서 자동 부여 (에이전트가 위조 불가).
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import { appendJournalSection } from "../state/journal"

export const ompAppendJournalTool: ToolDefinition = tool({
  description:
    "Append a new section to the challenge's journal.md (append-only progress log). " +
    "The section heading is automatically timestamped server-side. " +
    "Call this after omp_patch_state to record a human-readable summary of what you did. " +
    "journal.md is read-only for humans — never tell the user to edit it.",
  args: {
    challenge_dir: tool.schema
      .string()
      .describe("Absolute path to the challenge directory (parent of .omp/)"),
    heading: tool.schema
      .string()
      .describe(
        "Section heading (without ##). E.g. 'Reverser analysis complete', 'EnvSetup complete'.",
      ),
    body: tool.schema
      .string()
      .describe(
        "Markdown body for the section. Use tables, bullet lists, code blocks as appropriate. " +
        "This is what the human operator reads to understand what you found.",
      ),
  },
  execute: async ({ challenge_dir, heading, body }) => {
    try {
      appendJournalSection(challenge_dir, heading, body)
      return JSON.stringify({ ok: true })
    } catch (err) {
      return JSON.stringify({ error: "journal_write_failed", message: String(err) })
    }
  },
})
