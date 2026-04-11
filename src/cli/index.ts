#!/usr/bin/env bun
/**
 * omp — interactive CTF pwn auto-solve agent.
 * Like opencode, but for pwnables.
 */
// TODO(P2): When plugin.ts is ready, integrate createOmpSession() here
// Current implementation uses @anthropic-ai/sdk directly as a working fallback

import { createInterface } from "node:readline"
import { resolve } from "node:path"
import { existsSync } from "node:fs"
import Anthropic from "@anthropic-ai/sdk"

// ── CLI args ──────────────────────────────────────────────────────────────
const args = process.argv.slice(2)

if (args.includes("-h") || args.includes("--help")) {
  console.log(`
  oh-my-pwn (OmP) — CTF pwnable auto-solve agent

  Usage:
    omp                          Interactive mode
    omp <challenge-dir>          Interactive mode with challenge loaded

  Options:
    --model <model>   Model override (default: claude-sonnet-4-6)
    -h, --help        Show this help
    -v, --version     Show version
`)
  process.exit(0)
}

if (args.includes("-v") || args.includes("--version")) {
  console.log("omp v0.1.0")
  process.exit(0)
}

// Parse --model flag
let modelId = "claude-sonnet-4-6"
const modelIdx = args.indexOf("--model")
if (modelIdx !== -1 && args[modelIdx + 1]) {
  modelId = args[modelIdx + 1]
  args.splice(modelIdx, 2)
}

// Remaining arg = challenge dir
const challengeDir = args[0] ? resolve(args[0]) : undefined

// ── System prompt ─────────────────────────────────────────────────────────
const SYSTEM_PROMPT = `You are OmP (oh-my-pwn), a CTF pwnable auto-solve agent.
You analyze ELF binaries, find vulnerabilities, and write exploits.

Your pipeline: EnvSetup → Reverse → VulnHunt → Exploit → Verify

You have access to tools for file I/O and shell commands.
When the user gives you a challenge directory, you:
1. Check for binary + Dockerfile
2. Run EnvSetup (docker build, extract libc, checksec)
3. Reverse the binary (ghidra or source analysis)
4. Identify vulnerabilities
5. Write pwntools exploit
6. Verify against local docker container

Respond in Korean. Technical terms (checksec, tcache, FSOP, AAW, seccomp) stay in English.
${challengeDir ? `\nChallenge directory loaded: ${challengeDir}` : ""}`

// ── Tools ─────────────────────────────────────────────────────────────────
const tools: Anthropic.Tool[] = [
  {
    name: "bash",
    description: "Execute a shell command and return stdout/stderr.",
    input_schema: {
      type: "object" as const,
      properties: {
        command: { type: "string", description: "Shell command to execute" },
      },
      required: ["command"],
    },
  },
  {
    name: "read_file",
    description: "Read a file and return its contents.",
    input_schema: {
      type: "object" as const,
      properties: {
        path: { type: "string", description: "Absolute or relative file path" },
      },
      required: ["path"],
    },
  },
  {
    name: "write_file",
    description: "Write content to a file (creates or overwrites).",
    input_schema: {
      type: "object" as const,
      properties: {
        path: { type: "string", description: "File path" },
        content: { type: "string", description: "File content" },
      },
      required: ["path", "content"],
    },
  },
]

// ── Tool execution ────────────────────────────────────────────────────────
async function executeTool(name: string, input: Record<string, string>): Promise<string> {
  switch (name) {
    case "bash": {
      const proc = Bun.spawn(["bash", "-c", input.command], {
        stdout: "pipe",
        stderr: "pipe",
        cwd: challengeDir ?? process.cwd(),
      })
      const stdout = await new Response(proc.stdout).text()
      const stderr = await new Response(proc.stderr).text()
      await proc.exited
      const code = proc.exitCode
      return `exit code: ${code}\n${stdout}${stderr ? `\nstderr:\n${stderr}` : ""}`
    }
    case "read_file": {
      const p = resolve(challengeDir ?? process.cwd(), input.path)
      if (!existsSync(p)) return `ERROR: file not found: ${p}`
      return await Bun.file(p).text()
    }
    case "write_file": {
      const p = resolve(challengeDir ?? process.cwd(), input.path)
      await Bun.write(p, input.content)
      return `OK: wrote ${input.content.length} bytes to ${p}`
    }
    default:
      return `ERROR: unknown tool ${name}`
  }
}

// ── Chat loop ─────────────────────────────────────────────────────────────
const client = new Anthropic()
const messages: Anthropic.MessageParam[] = []

const rl = createInterface({
  input: process.stdin,
  output: process.stdout,
})

function prompt(): Promise<string> {
  return new Promise((resolve) => {
    rl.question("\x1b[36momp>\x1b[0m ", (answer) => resolve(answer))
  })
}

console.log("\x1b[1m")
console.log("  ┌─────────────────────────────────────┐")
console.log("  │     oh-my-pwn (OmP) v0.1.0          │")
console.log("  │     CTF Pwnable Auto-Solve Agent     │")
console.log("  └─────────────────────────────────────┘")
console.log("\x1b[0m")
console.log(`  model : ${modelId}`)
if (challengeDir) {
  console.log(`  target: ${challengeDir}`)
}
console.log(`  type "exit" to quit, "help" for commands\n`)

while (true) {
  const input = await prompt()
  if (!input.trim()) continue
  if (input.trim() === "exit" || input.trim() === "quit") {
    console.log("\nbye 👋\n")
    break
  }

  messages.push({ role: "user", content: input })

  try {
    // Agent loop: keep calling until no more tool_use
    let response = await client.messages.create({
      model: modelId,
      max_tokens: 8192,
      system: SYSTEM_PROMPT,
      tools,
      messages,
    })

    while (true) {
      // Collect assistant message
      const assistantContent: Anthropic.ContentBlock[] = [...response.content]
      messages.push({ role: "assistant", content: assistantContent })

      // Print text blocks
      for (const block of response.content) {
        if (block.type === "text") {
          console.log(`\n${block.text}\n`)
        }
      }

      // Check for tool use
      const toolUses = response.content.filter(
        (b): b is Anthropic.ToolUseBlock => b.type === "tool_use"
      )

      if (toolUses.length === 0 || response.stop_reason === "end_turn") {
        break
      }

      // Execute tools and collect results
      const toolResults: Anthropic.ToolResultBlockParam[] = []
      for (const tu of toolUses) {
        console.log(`  \x1b[33m⚡ ${tu.name}\x1b[0m: ${JSON.stringify(tu.input).slice(0, 120)}`)
        const result = await executeTool(tu.name, tu.input as Record<string, string>)
        const truncated = result.length > 10000 ? result.slice(0, 10000) + "\n...(truncated)" : result
        toolResults.push({
          type: "tool_result",
          tool_use_id: tu.id,
          content: truncated,
        })
      }

      messages.push({ role: "user", content: toolResults })

      // Continue the agent loop
      response = await client.messages.create({
        model: modelId,
        max_tokens: 8192,
        system: SYSTEM_PROMPT,
        tools,
        messages,
      })
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error(`\n  \x1b[31mERROR\x1b[0m: ${msg}\n`)
  }
}

rl.close()
