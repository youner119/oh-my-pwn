/**
 * Reverser research report template (English).
 *
 * Served by the `omp_get_template` tool. Structure:
 *   - `## Rules for filling this template` — template-local rules that
 *     only apply when the agent is filling this template. Cross-cutting
 *     rules (neutrality, state management, type inference, etc.) stay in
 *     the Reverser's system prompt.
 *   - `## Skeleton` — markdown skeleton (inside a code block) with
 *     `<placeholder>` markers. The agent emits the skeleton body verbatim,
 *     replacing each placeholder with actual content.
 *
 * The `omp_verify_template_output` tool parses the `## Skeleton` block
 * to extract required section headings and mechanically checks the
 * agent's output against them.
 */

export const reverserResearchEnTemplate = `# Template: reverser-research-en

## Rules for filling this template

Follow these rules when generating the English research report. These are
**template-local rules** — they apply only to this specific artifact.
Cross-cutting rules from your system prompt (neutrality, forbidden-words
list, state management, type inference, etc.) continue to apply on top of
these.

- **Audience:** human user (primary) + downstream agents (secondary). The
  user wants to get oriented on a new binary quickly. Downstream agents
  (VulnHunter, Exploiter) use this as a high-level narrative companion to
  the structured artifact at \`reverser-analysis.md\`.
- **Tone:** first-person singular is allowed and encouraged where natural
  ("I renamed \`FUN_00101255\` to \`run_two_round_input_echo\` after
  observing a 2-iteration for loop..."). Prose flows naturally rather
  than bullet-point form. This is the researcher's findings memo, not
  a reference doc.
- **Length:** no hard limit. Typical small-medium CTF: 300-800 words.
  Larger or more complex programs may need more — write as much as needed
  to convey understanding, no more. Brevity is a virtue but completeness
  wins over brevity when there is genuine complexity to explain.
- **Relationship to the structured artifact:** the reference tables,
  function map, and detailed per-function sections live in
  \`reverser-analysis.md\`. Do NOT duplicate tables here. Point the reader
  at the structured artifact for exact offsets, addresses, or full
  pseudocode listings.
- **Neutrality (reminder):** the forbidden-words list from your Reverser
  system prompt still applies. Narrative form strongly tempts toward
  judgment phrases ("suggests", "indicates", "likely", "may be"); resist
  them. Stick to observed facts with rich descriptive language. The
  \`omp_verify_template_output\` tool checks for unambiguous vulnerability
  vocabulary mechanically — any hit will fail verification.
- **Placeholders:** replace every \`<...>\` marker in the skeleton with
  actual content. Leaving any placeholder in the final output is a
  verification failure.
- **Section order:** preserve the exact section headings and order from
  the skeleton. The verification tool parses the skeleton for required
  sections and checks each one against your output.

## Skeleton

The block below is the skeleton. Emit the body of this markdown block
verbatim, replacing every \`<...>\` with actual content. Do NOT emit the
surrounding \`\\\`\\\`\\\`markdown\` fence — that is just framing for this
template file.

\\\`\\\`\\\`markdown
# Reverser Research Report: <binary_basename>

_Generated: <ISO timestamp> | Binary sha: <sha256> | Analysis roots: <comma-separated analysis roots, e.g. main, _init, _fini, _start>_

## Executive summary

<1-2 paragraphs, narrative prose. Answer "what IS this program?" in
human terms. Reference the program type (menu-driven / server /
one-shot / trigger-based), the I/O model (stdin / socket / file),
and the major state (global buffer, heap array, state machine mode,
etc.). Neutral facts.>

## Analysis approach

<2-3 sentences describing what roots were analyzed, what BFS depth was
used, how many functions ended up in the analysis set, and what
ghidra-mcp tools you invoked (decompile_function, rename_function,
batch_set_variable_types, batch_set_comments, etc.). Pure process
narrative.>

## What each function does

<Walk the user-defined functions in call order from main outward. For
each, 2-4 sentences in prose. Describe what the function does, how it
relates to its callers and callees, and what state it touches. Use the
renamed names you gave the functions. Focus on functions that matter
for understanding the program's behavior. Do NOT restate the full
function map — that is in reverser-analysis.md.>

## Types I applied

<Prose recap of type refinements. Explain the reasoning behind each
refinement in 1-2 sentences: what pattern was observed, what type was
chosen. This is the narrative version of the "Types introduced by
Reverser" section in the structured artifact. Omit this section if you
applied zero type refinements.>

## Data entry points

<Where does attacker-controlled data enter the program? List the
functions that call user-input sinks (\`read\`, \`recv\`, \`fgets\`,
\`scanf\`, etc.) and what buffer or global the data lands in. Neutral
description — state where the entry point is, not what can be done
with it.>

## Stack frames of interest

<Summarize 1-3 functions whose stack frames contain meaningful locals,
in prose form. Reference offsets and distances from the structured
artifact's per-function "Stack frame" subsections; do NOT repeat the
full tables here. Omit this section entirely if no function has a
non-trivial stack frame.>

## Handoff notes

<Closing 1-2 sentences. Point VulnHunter and Exploiter at the
structured artifact (\`reverser-analysis.md\`) as their next read, and
note any structural fact that is especially relevant for their work.
Do NOT suggest what vulnerabilities to look for.>
\\\`\\\`\\\`
`
