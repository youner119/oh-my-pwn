/**
 * T06 — dangerous function knowledge base for agent prompt injection.
 *
 * These constants are consumed by the Reverser agent (T07) prompt and
 * downstream agents (VulnHunter) to identify security-relevant function
 * calls in the binary.
 *
 * Not a bridge wrapper — the Reverser agent calls ghidra-mcp tools directly
 * via MCP and uses this knowledge to reason about what it finds.
 */

/**
 * Map of function names to human-readable exploitation reasons.
 * Injected into agent prompts so the LLM knows why each function matters.
 */
export const DANGEROUS_FUNCTION_REASONS: Readonly<Record<string, string>> = {
  gets: "unbounded read, guaranteed stack BOF",
  scanf: "unbounded read, stack BOF when width specifier omitted",
  sprintf: "unbounded write into fixed-size destination buffer",
  strcpy: "unbounded copy, destination overflow",
  strcat: "unbounded concatenation, destination overflow",
  printf: "potential format string if user-controlled",
  fprintf: "potential format string if user-controlled",
  snprintf: "potential format string if user-controlled (despite size limit)",
  system: "arbitrary command execution primitive",
  execve: "arbitrary command execution primitive",
  execvp: "arbitrary command execution primitive",
  popen: "arbitrary command execution primitive",
  mprotect: "memory permission change — RWX shellcode staging",
  mmap: "anonymous RWX mapping possible",
  free: "double-free / UAF potential",
  malloc: "heap allocation — track for heap exploitation",
  realloc: "heap reallocation — track for heap exploitation",
  calloc: "heap allocation — track for heap exploitation",
  read: "unbounded read if size from user input",
  memcpy: "buffer overflow if size from user input",
  memmove: "buffer overflow if size from user input",
  strncpy: "off-by-one if size == buffer size (no null terminator)",
  strtok: "not reentrant, subtle state corruption",
  setbuf: "setvbuf / setbuf manipulation — may disable buffering for exploit stability",
  setvbuf: "setvbuf / setbuf manipulation — may disable buffering for exploit stability",
}

/** Set of function names considered dangerous for quick lookup. */
export const DANGEROUS_FUNCTIONS: ReadonlySet<string> = new Set(
  Object.keys(DANGEROUS_FUNCTION_REASONS),
)

/**
 * Formats the dangerous function knowledge as a markdown table suitable
 * for injection into an agent system prompt.
 */
export function formatDangerousFunctionsForPrompt(): string {
  const header = "| Function | Exploitation Reason |"
  const sep = "|---|---|"
  const rows = Object.entries(DANGEROUS_FUNCTION_REASONS)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([fn, reason]) => `| \`${fn}\` | ${reason} |`)
  return [header, sep, ...rows].join("\n")
}
