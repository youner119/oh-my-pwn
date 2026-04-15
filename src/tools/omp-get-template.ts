/**
 * omp_get_template — fetch a template for agent-written artifacts.
 *
 * The agent calls this when it's about to generate a template-based
 * artifact (e.g., Reverser fetching `reverser-research-en` right before
 * writing the English research report). The returned template contains
 * both template-local rules and a skeleton — the agent reads the rules,
 * fills in the skeleton placeholders, and writes the artifact.
 *
 * Templates are bundled into the plugin at build time from
 * `src/templates/*.ts`. Editing a template requires rebuilding the
 * plugin (`bun run build:plugin`) and restarting `omp`.
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import { getOmpTemplate, listOmpTemplateKinds } from "../templates"

export const ompGetTemplateTool: ToolDefinition = tool({
  description:
    "Fetch an OmP template for a template-based artifact. Templates contain " +
    "template-local rules (that only apply when filling this specific template) " +
    "plus a markdown skeleton with <placeholder> markers. The agent reads the " +
    "rules, fills in the placeholders, and writes the artifact. " +
    "Known kinds: 'reverser-research-en', 'reverser-research-ko'. " +
    "Pass kind='list' to get the full list of available kinds. " +
    "After writing the artifact, verify it with omp_verify_template_output " +
    "before finalizing.",
  args: {
    kind: tool.schema
      .string()
      .describe(
        "The template kind. Examples: 'reverser-research-en', " +
        "'reverser-research-ko'. Pass 'list' to enumerate available kinds.",
      ),
  },
  execute: async ({ kind }) => {
    if (kind === "list") {
      return JSON.stringify({
        ok: true,
        kinds: listOmpTemplateKinds(),
      })
    }
    const template = getOmpTemplate(kind)
    if (template === null) {
      return JSON.stringify({
        error: "unknown_template",
        message:
          `No template with kind '${kind}'. ` +
          `Call with kind='list' to see available kinds.`,
        available: listOmpTemplateKinds(),
      })
    }
    return JSON.stringify({
      ok: true,
      kind,
      template,
    })
  },
})
