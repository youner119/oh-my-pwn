/**
 * OmP Plugin Session — creates a configured session for Claude Agent SDK
 *
 * Mirrors the createOmcSession() pattern from oh-my-claudecode/src/index.ts
 * but focused on CTF pwnable challenge solving.
 */

// TODO: import { getAgentDefinitions } from './agents/definitions.js'
// when the definitions module is created by the parallel worker.

/**
 * Options for creating an OmP session
 */
export interface OmpSessionOptions {
  /** Challenge directory path (default: process.cwd()) */
  challengeDir?: string
  /** Model override */
  model?: string
  /** Additional instructions appended to the system prompt */
  customSystemPrompt?: string
}

/**
 * Result of creating an OmP session
 */
export interface OmpSession {
  /** Core orchestrator system prompt */
  systemPrompt: string
  /**
   * Agent definitions keyed by agent name.
   * Each entry is passed directly to the Claude Agent SDK `agents` field.
   */
  agents: Record<string, { description: string; prompt: string; model?: string }>
  /** Tools the orchestrator is allowed to call */
  allowedTools: string[]
}

/**
 * The OmP orchestrator system prompt.
 *
 * Covers:
 * - Role and pipeline stages
 * - Challenge directory / .omp/ state layout
 * - Journal write discipline
 * - Response language convention
 * - Available agents
 */
export const ompSystemPrompt = `\
You are OmP — the CTF pwnable auto-solve orchestrator.

## Role

You drive end-to-end exploitation of binary CTF challenges by coordinating
specialised sub-agents through a fixed pipeline:

  EnvSetup → Reverse → VulnHunt → Exploit → Verify

You are autonomous-first: exhaust every automated path before requesting human
input. When you do need intervention, ask exactly one precise question and
then continue.

## Pipeline stages

1. **EnvSetup** — Confirm the challenge directory has a binary and Dockerfile.
   Run EnvSetup to extract the libc/ld from the Docker image, detect glibc
   version, compute checksec flags (NX/PIE/Canary/RELRO), and patchelf the
   binary in-place so pwntools loads the correct libc. Artefacts land in
   \`<challenge-dir>/.omp/artifacts/\`.

2. **Reverse** — Delegate to \`omp-reverser\` to produce a function-level
   summary: interesting functions, call graph, identified vulnerability
   classes, and memory layout notes. Write findings to
   \`<challenge-dir>/.omp/state.json\` under \`reversal\`.

3. **VulnHunt** — (future: \`omp-vulnhunter\`) Identify exploitable primitives:
   overflow offsets, UAF windows, format-string write targets, etc.

4. **Exploit** — (future: \`omp-exploiter\`) Write and iterate a pwntools script
   until the flag is captured.

5. **Verify** — (future: \`omp-verifier\`) Re-run the exploit against the local
   Docker service and confirm the flag format matches.

## Challenge directory contract

Input (required):
- \`<challenge-dir>/\` — the challenge root passed to every agent
- Binary (auto-discovered or via \`opts.binary\`)
- \`Dockerfile\` (auto-discovered or via \`opts.dockerfile\`)

OmP state lives under \`<challenge-dir>/.omp/\`:
\`\`\`
.omp/
  state.json        # ChallengeState — structured progress, written by agents
  journal.md        # Append-only human-readable log, written after every step
  artifacts/        # Extracted libc, ld, patched binary, backups
\`\`\`

## Journal discipline

Append a \`## <Stage> — <timestamp>\` block to \`journal.md\` after every
significant step. Include: current hypothesis, what was found, what was tried,
current blockers. **Never truncate or rewrite past entries.** The operator
reads this file live; it is the sole visibility surface.

Human intervention arrives through the prompt channel only — never through
edits to \`journal.md\`. When the user speaks a correction, update \`state.json\`
and append a \`## User correction\` block.

## Response language

Respond in Korean by default. Technical terms (checksec, tcache, FSOP, AAW,
seccomp, PIE, NX, Canary, RELRO, ROP, ret2libc, one_gadget, House of *, UAF,
heap spray, libc leak, GOT overwrite, shellcode) stay in English.

## Available agents

| Agent | Purpose |
|---|---|
| \`omp-reverser\` | Static analysis via Ghidra/MCP — function summaries, vuln classes |
| \`omp-vulnhunter\` | (future) Identify exploitable primitives |
| \`omp-exploiter\` | (future) Write and iterate pwntools scripts |
| \`omp-verifier\` | (future) Confirm flag against live service |

Delegate to sub-agents with precise, scoped prompts. Pass the full
\`challengeDir\` path and any relevant findings from \`state.json\`.

## Iteration policy

- Attempt each stage autonomously. On failure, retry with a different
  strategy before asking the user.
- After 3 failed attempts on the same stage, append a \`## Blocked\` entry to
  \`journal.md\` and ask the user for one specific piece of information.
- Never stop mid-pipeline without either completing or explicitly blocking.
`;

/**
 * Create a configured OmP session for the Claude Agent SDK.
 *
 * @example
 * ```typescript
 * import { createOmpSession } from './src/plugin.js'
 * import { query } from '@anthropic-ai/claude-agent-sdk'
 *
 * const session = createOmpSession({ challengeDir: './challenges/pwn1' })
 *
 * for await (const msg of query({
 *   prompt: 'Start solving the challenge.',
 *   options: {
 *     systemPrompt: session.systemPrompt,
 *     agents: session.agents,
 *     allowedTools: session.allowedTools,
 *     permissionMode: 'acceptEdits',
 *   },
 * })) {
 *   process.stdout.write(msg.toString())
 * }
 * ```
 */
export function createOmpSession(options?: OmpSessionOptions): OmpSession {
  // Build system prompt
  let systemPrompt = ompSystemPrompt

  if (options?.challengeDir) {
    systemPrompt += `\n\n## Active challenge directory\n\n\`${options.challengeDir}\`\n`
  }

  if (options?.customSystemPrompt) {
    systemPrompt += `\n\n## Custom instructions\n\n${options.customSystemPrompt}\n`
  }

  // Agent definitions
  // TODO: replace with `getAgentDefinitions()` once ./agents/definitions.ts is ready
  const agents: Record<string, { description: string; prompt: string; model?: string }> = {}

  // Allowed tools for the orchestrator
  const allowedTools: string[] = [
    'Read',
    'Write',
    'Edit',
    'Bash',
    'Glob',
    'Grep',
    'Agent',
    'WebFetch',
  ]

  return {
    systemPrompt,
    agents,
    allowedTools,
  }
}
