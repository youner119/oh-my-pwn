/**
 * Lenient Dockerfile parser focused on the four pieces of information
 * EnvSetup needs:
 *
 *   - **Exposed ports** — `EXPOSE <port>` lines, parsed in order. The first
 *     port becomes `RemoteEntrypoint.port`.
 *   - **CMD / ENTRYPOINT** — the literal command string (last occurrence
 *     wins, like Docker itself).
 *   - **Wrapper** — recognised by keyword (`ynetd`, `socat`, `xinetd`,
 *     `ncat`, `nc`). Used to fill `RemoteEntrypoint.wrapper`.
 *   - **Seccomp hint** — true if the Dockerfile mentions `--security-opt
 *     seccomp=` or invokes `prctl` / `seccomp` somewhere. Best-effort hint
 *     only; the real seccomp policy will be inspected at runtime by a
 *     future task.
 *
 * Lenient by design. Unknown directives, comments, line continuations, and
 * multi-stage `FROM ... AS stage` blocks are accepted without complaint —
 * we never throw a parse error. Anything we cannot recognise is silently
 * ignored, and the resulting partial result still flows through the rest
 * of the EnvSetup pipeline.
 *
 * Caller-side note: this module is exported as a low-level building block
 * (per the T04 pre-work decision). A future LLM agent could call it
 * directly on a candidate Dockerfile and reason about the output.
 */

import { readFileSync } from "node:fs"

export interface ParsedDockerfile {
  /** All `EXPOSE` ports, in source order. May be empty. */
  exposedPorts: number[]
  /** Last `ENTRYPOINT` directive value (raw, after the directive). */
  entrypoint?: string
  /** Last `CMD` directive value (raw, after the directive). */
  cmd?: string
  /**
   * Recognised wrapper keyword observed in CMD / ENTRYPOINT, e.g. "ynetd",
   * "socat", "xinetd", "ncat". Undefined when nothing matches.
   */
  wrapper?: string
  /**
   * Best-effort hint that the runtime applies a seccomp policy. True iff:
   *   - the Dockerfile uses `--security-opt seccomp=...` (rare in build
   *     time, more common in run-time, but some folks document it here),
   *     OR
   *   - the Dockerfile invokes `prctl(PR_SET_SECCOMP)` or installs a
   *     `seccomp-bpf` binary,
   *     OR
   *   - any line contains the case-insensitive token `seccomp`.
   * Always interpret as a hint, never a guarantee.
   */
  hasSeccompFlag: boolean
  /** Path the parser was given (echoed for caller convenience). */
  dockerfilePath: string
}

const RECOGNISED_WRAPPERS: readonly string[] = [
  "ynetd",
  "socat",
  "xinetd",
  "ncat",
  // bare "nc" is intentionally omitted: too many false positives in CMD
  // strings like `echo "abc" | nc-something`. Match it only as a whole word
  // below.
]

/**
 * Read and parse a Dockerfile from disk.
 *
 * Never throws; on read errors the function returns a result with all
 * fields empty/false and `dockerfilePath` echoed back. The caller can
 * inspect the empty result and fall back to defaults.
 */
export function parseDockerfile(dockerfilePath: string): ParsedDockerfile {
  let raw: string
  try {
    raw = readFileSync(dockerfilePath, "utf-8")
  } catch {
    return {
      exposedPorts: [],
      hasSeccompFlag: false,
      dockerfilePath,
    }
  }
  return parseDockerfileText(raw, dockerfilePath)
}

/**
 * Pure-text variant of {@link parseDockerfile}. Exposed for unit tests so
 * they can pass synthetic Dockerfile contents directly.
 */
export function parseDockerfileText(
  raw: string,
  dockerfilePath = "<inline>",
): ParsedDockerfile {
  const lines = unfoldContinuations(raw)
  const result: ParsedDockerfile = {
    exposedPorts: [],
    hasSeccompFlag: false,
    dockerfilePath,
  }

  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed === "" || trimmed.startsWith("#")) {
      continue
    }

    // Directive is the first whitespace-delimited token, case-insensitive.
    const match = trimmed.match(/^([A-Za-z]+)\s+(.*)$/u)
    if (match === null) {
      continue
    }
    const directive = match[1]!.toUpperCase()
    const value = match[2]!

    switch (directive) {
      case "EXPOSE": {
        for (const token of value.split(/\s+/u)) {
          // Strip optional /tcp or /udp suffix.
          const portStr = token.split("/")[0]!
          const port = Number.parseInt(portStr, 10)
          if (Number.isFinite(port) && port > 0 && port < 65536) {
            result.exposedPorts.push(port)
          }
        }
        break
      }
      case "ENTRYPOINT": {
        result.entrypoint = value
        const wrapper = recogniseWrapper(value)
        if (wrapper !== undefined) {
          result.wrapper = wrapper
        }
        break
      }
      case "CMD": {
        result.cmd = value
        // Don't overwrite a wrapper that was already set by ENTRYPOINT —
        // ENTRYPOINT takes precedence (closer to docker semantics).
        if (result.wrapper === undefined) {
          const wrapper = recogniseWrapper(value)
          if (wrapper !== undefined) {
            result.wrapper = wrapper
          }
        }
        break
      }
      default:
        // Other directives (FROM, RUN, COPY, USER, ARG, ENV, ...) are
        // silently ignored. We only need the four data points above.
        break
    }
  }

  // Seccomp hint scan runs over the entire raw text so it can match content
  // in RUN lines, comments, etc.
  result.hasSeccompFlag = detectSeccompHint(raw)

  return result
}

/**
 * Collapse `\` line-continuations so the directive parser can treat each
 * logical instruction as a single line. Preserves the count of physical
 * lines for accurate (eventual) error messages.
 */
function unfoldContinuations(raw: string): string[] {
  const physical = raw.split(/\r?\n/u)
  const logical: string[] = []
  let buffer = ""
  for (const line of physical) {
    const stripped = line.replace(/\r$/u, "")
    if (stripped.endsWith("\\")) {
      buffer += `${stripped.slice(0, -1)} `
      continue
    }
    logical.push(buffer + stripped)
    buffer = ""
  }
  if (buffer !== "") {
    logical.push(buffer)
  }
  return logical
}

function recogniseWrapper(value: string): string | undefined {
  // Strip JSON-array form: ["ynetd", "-p", "1234", "/chall"] → "ynetd -p 1234 /chall"
  const flat = value
    .replace(/^\s*\[/u, "")
    .replace(/\]\s*$/u, "")
    .replace(/[",]/gu, " ")
  const tokens = flat.split(/\s+/u).filter((t) => t !== "")
  for (const token of tokens) {
    const lower = token.toLowerCase()
    // Strip surrounding paths so `/usr/bin/ynetd` matches `ynetd`.
    const basename = lower.split("/").pop() ?? lower
    if (RECOGNISED_WRAPPERS.includes(basename)) {
      return basename
    }
    // Whole-word match for bare `nc` to avoid `incoming` etc.
    if (basename === "nc") {
      return "nc"
    }
  }
  return undefined
}

function detectSeccompHint(raw: string): boolean {
  if (/--security-opt\s+seccomp=/iu.test(raw)) {
    return true
  }
  if (/PR_SET_SECCOMP/u.test(raw)) {
    return true
  }
  if (/seccomp[-_]?bpf/iu.test(raw)) {
    return true
  }
  // Substring 'seccomp' anywhere in the file. Catches `libseccomp-dev`,
  // `seccomp-tools`, plain documentation. False positives are acceptable —
  // this field is documented as a hint, not a guarantee.
  if (/seccomp/iu.test(raw)) {
    return true
  }
  return false
}
