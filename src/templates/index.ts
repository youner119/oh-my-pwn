/**
 * OmP template registry.
 *
 * Templates are reusable markdown specifications for agent-written
 * artifacts. Each template has a `## Rules for filling this template`
 * section (template-local rules that only apply when filling this
 * template) and a `## Skeleton` section (the markdown structure to
 * fill in, wrapped in a `\`\`\`markdown` code block with `<placeholder>`
 * markers).
 *
 * Agents use `omp_get_template(kind)` to fetch a template at the point
 * they need it, and `omp_verify_template_output(kind, content)` to
 * mechanically verify the generated output conforms to the template
 * before finalizing.
 *
 * Cross-cutting rules (neutrality, forbidden-words list, state
 * management, etc.) stay in each agent's system prompt. Template-local
 * rules travel with the template and are loaded when the tool is
 * called, benefiting from recency bias in the LLM's attention.
 *
 * Adding a new template:
 *   1. Create `src/templates/<kind>.ts` exporting a const string.
 *   2. Add the entry to `OMP_TEMPLATES` below.
 *   3. If the new template has different verification semantics, add
 *      a `KIND_CONFIGS` entry in `src/tools/omp-verify-template-output.ts`.
 */

import { reverserResearchEnTemplate } from "./reverser-research-en"
import { reverserResearchKoTemplate } from "./reverser-research-ko"

export const OMP_TEMPLATES = {
  "reverser-research-en": reverserResearchEnTemplate,
  "reverser-research-ko": reverserResearchKoTemplate,
} as const

export type OmpTemplateKind = keyof typeof OMP_TEMPLATES

/** Fetch a template by kind, or null if the kind is unknown. */
export function getOmpTemplate(kind: string): string | null {
  return (OMP_TEMPLATES as Record<string, string>)[kind] ?? null
}

/** List all available template kinds. */
export function listOmpTemplateKinds(): string[] {
  return Object.keys(OMP_TEMPLATES)
}
