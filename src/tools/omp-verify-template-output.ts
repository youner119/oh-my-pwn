/**
 * omp_verify_template_output — mechanical structural check for
 * template-based artifacts.
 *
 * The agent calls this AFTER writing a template-based artifact to catch
 * mechanical failures: missing sections, unfilled placeholders, forbidden
 * vulnerability vocabulary, Korean translations of English technical
 * terms. Returns `{ ok: true }` on success or `{ ok: false, violations }`
 * with a per-violation list the agent can act on.
 *
 * This is a deterministic structural check only — it does not verify
 * semantic correctness (e.g. "does the purpose paragraph actually
 * describe what the function does"). That's the agent's self-review
 * layer (Pass B).
 *
 * Extending this tool to a new template:
 *   1. Add a `KIND_CONFIGS` entry for the new kind with appropriate
 *      check flags.
 *   2. If new check categories are needed, add them to the execute()
 *      flow and the Violation union.
 */

import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import { getOmpTemplate } from "../templates"

/**
 * Unambiguous vulnerability vocabulary that must never appear in any
 * Reverser output, regardless of language. These are substring-matched
 * case-insensitively. Common English modal verbs (may, likely, could,
 * allows, enables) are intentionally excluded to avoid false positives;
 * the Reverser's prompt + self-check cover those.
 */
const FORBIDDEN_EN_WORDS: readonly string[] = [
  "vulnerability",
  "vulnerabilities",
  "vulnerable",
  "exploit",
  "exploits",
  "exploitable",
  "exploitation",
  "primitive",
  "bof",
  "overflow",
  "leak primitive",
  "rop",
  "uaf",
  "use-after-free",
  "use after free",
  "format string bug",
  "canary bypass",
  "rce",
  "arbitrary read",
  "arbitrary write",
  "info leak",
  "susceptible",
  "insecure",
]

/**
 * Korean-specific vulnerability vocabulary. Parallels the English list.
 * Applied to the Korean research report template output.
 */
const FORBIDDEN_KO_WORDS: readonly string[] = [
  "취약점",
  "취약성",
  "익스플로잇",
  "오버플로우",
  "유출",
  "누출",
  "악용",
]

/**
 * Korean translations of English technical terms that MUST stay in
 * English per project convention. Any of these appearing in a KO
 * template output is a translation violation — the original English
 * term should have been preserved.
 */
const KO_FORBIDDEN_TECHNICAL_TRANSLATIONS: readonly string[] = [
  "스택",
  "힙",
  "캐나리",
  "카나리",
  "버퍼",
]

interface TemplateConfig {
  extractRequiredSections: boolean
  checkForbiddenEn: boolean
  checkForbiddenKo: boolean
  checkKoTechnicalTranslations: boolean
  checkUnfilledPlaceholders: boolean
}

/**
 * Per-kind configuration for what checks to run. Keyed by template kind.
 * Adding a new template kind means adding an entry here.
 */
const KIND_CONFIGS: Record<string, TemplateConfig> = {
  "reverser-research-en": {
    extractRequiredSections: true,
    checkForbiddenEn: true,
    checkForbiddenKo: false,
    checkKoTechnicalTranslations: false,
    checkUnfilledPlaceholders: true,
  },
  "reverser-research-ko": {
    extractRequiredSections: true,
    checkForbiddenEn: true,
    checkForbiddenKo: true,
    checkKoTechnicalTranslations: true,
    checkUnfilledPlaceholders: true,
  },
}

interface Violation {
  severity: "error"
  kind: string
  message: string
  detail?: unknown
}

/**
 * Parse a template's Skeleton code block to extract the H2 section
 * headings the agent output must contain.
 *
 * The skeleton lives inside a fenced `\`\`\`markdown ... \`\`\`` block under
 * the `## Skeleton` heading in the template file. We find that block and
 * extract all `## Xxx` headings inside it. The template's top H1 title
 * (`# Reverser Research Report: ...`) is intentionally ignored — it is
 * not a section requirement but a file title.
 */
function extractRequiredSectionsFromTemplate(template: string): string[] {
  // Find the `## Skeleton` section, then the markdown code block inside it.
  const skeletonMatch = template.match(
    /## Skeleton[\s\S]*?```markdown\n([\s\S]*?)\n```/,
  )
  if (skeletonMatch === null) {
    return []
  }
  const skeleton = skeletonMatch[1] ?? ""
  const headings: string[] = []
  for (const line of skeleton.split("\n")) {
    const h2Match = line.match(/^## (.+?)\s*$/)
    if (h2Match !== null) {
      headings.push((h2Match[1] ?? "").trim())
    }
  }
  return headings
}

/**
 * Find forbidden words via case-insensitive substring match. Returns
 * the list of words that appeared at least once.
 */
function findForbiddenWords(
  content: string,
  words: readonly string[],
): string[] {
  const lowered = content.toLowerCase()
  const hits: string[] = []
  for (const w of words) {
    if (lowered.includes(w.toLowerCase())) {
      hits.push(w)
    }
  }
  return hits
}

/**
 * Find Korean forbidden substrings. Korean doesn't use Western word
 * boundaries, so plain substring match is used. This may produce
 * occasional false positives (e.g. `힙` inside a compound word like
 * `힙입니다`), which is acceptable for the tight-CTF vocabulary domain
 * this tool serves.
 */
function findForbiddenKoSubstrings(
  content: string,
  words: readonly string[],
): string[] {
  const hits: string[] = []
  for (const w of words) {
    if (content.includes(w)) {
      hits.push(w)
    }
  }
  return hits
}

/**
 * Detect unfilled `<...>` placeholders. The skeleton's placeholders are
 * angle-bracketed prose markers like `<1-2 paragraphs, narrative ...>`.
 * We match `<` followed by at least one space-containing or
 * hyphen-joined-word sequence to avoid false-positives on HTML-like
 * tags, email addresses, or generic type notation (`<int>`, `<char>`).
 */
function findUnfilledPlaceholders(content: string): string[] {
  const matches = content.match(/<[^>\n]{3,}?>/g)
  if (matches === null) {
    return []
  }
  return matches.filter(
    (m) => m.includes(" ") || /[a-z]+-[a-z]+/i.test(m),
  )
}

export const ompVerifyTemplateOutputTool: ToolDefinition = tool({
  description:
    "Mechanically verify that a template-based artifact conforms to its " +
    "template. Checks: (1) all required sections from the template's " +
    "skeleton appear in the content, (2) no <...> placeholders remain " +
    "unfilled, (3) no forbidden English vulnerability vocabulary appears, " +
    "(4) no forbidden Korean vulnerability vocabulary appears (KO templates), " +
    "(5) no Korean translations of English technical terms appear (KO " +
    "templates). Returns { ok: true } on success or { ok: false, " +
    "violations: [...] } on failure. Call this after writing a " +
    "template-based artifact; if verification fails, fix the specific " +
    "violations and re-write the artifact, then re-verify. Max 2 retries " +
    "is the standard policy — after that, mark the artifact tentative and " +
    "record the failure in the journal.",
  args: {
    kind: tool.schema
      .string()
      .describe(
        "Template kind, e.g. 'reverser-research-en', 'reverser-research-ko'.",
      ),
    content: tool.schema
      .string()
      .describe(
        "The generated content to verify. Pass the full text of the " +
        "artifact you just wrote (or are about to write).",
      ),
  },
  execute: async ({ kind, content }) => {
    const config = KIND_CONFIGS[kind]
    if (config === undefined) {
      return JSON.stringify({
        error: "unknown_template",
        message:
          `No verification config for kind '${kind}'. ` +
          `Known kinds: ${Object.keys(KIND_CONFIGS).join(", ")}`,
      })
    }

    const template = getOmpTemplate(kind)
    if (template === null) {
      return JSON.stringify({
        error: "template_not_found",
        message:
          `Template file for '${kind}' is missing. ` +
          `This is a plugin build issue, not an agent error.`,
      })
    }

    const violations: Violation[] = []

    // Check 1: required sections from the template's skeleton.
    if (config.extractRequiredSections) {
      const required = extractRequiredSectionsFromTemplate(template)
      for (const section of required) {
        // Flexible matching: allow an optional ` (한국어 translation)` suffix
        // on Korean template section headings.
        const escapedSection = section.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
        const pattern = new RegExp(
          `^##\\s+${escapedSection}(?:\\s+\\([^)]+\\))?\\s*$`,
          "m",
        )
        if (!pattern.test(content)) {
          violations.push({
            severity: "error",
            kind: "missing_section",
            message: `Required section "## ${section}" not found in output`,
            detail: { section },
          })
        }
      }
    }

    // Check 2: unfilled placeholders.
    if (config.checkUnfilledPlaceholders) {
      const placeholders = findUnfilledPlaceholders(content)
      if (placeholders.length > 0) {
        violations.push({
          severity: "error",
          kind: "unfilled_placeholder",
          message:
            `${placeholders.length} unfilled placeholder(s) remain in the output`,
          detail: { markers: placeholders.slice(0, 5) },
        })
      }
    }

    // Check 3: English forbidden words.
    if (config.checkForbiddenEn) {
      const hits = findForbiddenWords(content, FORBIDDEN_EN_WORDS)
      if (hits.length > 0) {
        violations.push({
          severity: "error",
          kind: "forbidden_en_word",
          message:
            `Forbidden English vulnerability vocabulary appears in output: ${hits.join(", ")}`,
          detail: { words: hits },
        })
      }
    }

    // Check 4: Korean forbidden words.
    if (config.checkForbiddenKo) {
      const hits = findForbiddenKoSubstrings(content, FORBIDDEN_KO_WORDS)
      if (hits.length > 0) {
        violations.push({
          severity: "error",
          kind: "forbidden_ko_word",
          message:
            `Forbidden Korean vulnerability vocabulary appears in output: ${hits.join(", ")}`,
          detail: { words: hits },
        })
      }
    }

    // Check 5: Korean technical-term translations.
    if (config.checkKoTechnicalTranslations) {
      const hits = findForbiddenKoSubstrings(
        content,
        KO_FORBIDDEN_TECHNICAL_TRANSLATIONS,
      )
      if (hits.length > 0) {
        violations.push({
          severity: "error",
          kind: "ko_technical_translation",
          message:
            `Korean translation of English technical term(s) found — ` +
            `these must stay in English: ${hits.join(", ")}`,
          detail: { words: hits },
        })
      }
    }

    if (violations.length === 0) {
      return JSON.stringify({ ok: true, kind })
    }
    return JSON.stringify({
      ok: false,
      kind,
      violations,
    })
  },
})
