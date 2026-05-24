/**
 * Binary detection helpers, reused by the omp-setup agent's Phase 0 (Detect)
 * path per `.omc/specs/contract-load-detect-split.md` (D2).
 *
 * - {@link isElf} / {@link isExecutable} — cheap filesystem-level predicates.
 * - {@link looksLikeSharedObject} — basename heuristic to drop libc/ld files.
 * - {@link detectBinary} — pick the executable ELF candidates in `challengeDir`
 *   and return a discriminated {@link DetectBinaryResult} (`"ok"` / `"none"` /
 *   `"multiple"`). Callers decide how to handle non-`"ok"` outcomes (the setup
 *   agent surfaces `"multiple"` to the orchestrator as a `setup_blocker.kind`
 *   `"ambiguous-binary"`, and treats `"none"` as the no-binary unsupported
 *   classification).
 *
 * No I/O outside of `node:fs` synchronous calls.
 */

import {
  closeSync,
  openSync,
  readSync,
  readdirSync,
  statSync,
} from "node:fs"
import { join } from "node:path"

/** ELF magic bytes: 0x7F 'E' 'L' 'F'. */
const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46])

/**
 * File-name patterns that look like libc, ld, or other shared objects rather
 * than the challenge binary. Matched case-insensitively against the basename.
 *
 * Kept conservative on purpose: a CTF binary is sometimes named oddly
 * (`vuln`, `pwn`, `chall`, `app`, `notes`, ...) so we exclude only patterns
 * that are *clearly* not the target. Anything else is left to the executable-
 * bit filter.
 */
const SHARED_OBJECT_PATTERNS: readonly RegExp[] = [
  /\.so($|\.)/iu, // foo.so, libc.so.6, libfoo.so.1.2
  /^ld[-.]/iu, // ld-linux-x86-64.so.2, ld-2.31.so, ld.so
  /^libc[-.]/iu, // libc-2.31.so, libc.so.6
  /^libpthread[-.]/iu,
  /^libdl[-.]/iu,
  /^libm[-.]/iu,
  /^libstdc\+\+[-.]/iu,
  /^libgcc_s[-.]/iu,
]

/** True iff the first 4 bytes of `path` are the ELF magic. */
export function isElf(path: string): boolean {
  let fd: number
  try {
    fd = openSync(path, "r")
  } catch {
    return false
  }
  try {
    const buf = Buffer.alloc(4)
    const bytes = readSync(fd, buf, 0, 4, 0)
    if (bytes < 4) {
      return false
    }
    return buf.equals(ELF_MAGIC)
  } catch {
    return false
  } finally {
    closeSync(fd)
  }
}

/** True iff `path` has at least one execute bit set in its mode. */
export function isExecutable(path: string): boolean {
  try {
    const s = statSync(path)
    return (s.mode & 0o111) !== 0
  } catch {
    return false
  }
}

/** True iff the basename matches one of {@link SHARED_OBJECT_PATTERNS}. */
export function looksLikeSharedObject(basename: string): boolean {
  return SHARED_OBJECT_PATTERNS.some((rx) => rx.test(basename))
}

/**
 * Result of {@link detectBinary} — a discriminated union the caller can
 * pattern-match on. `detectBinary` never throws on detection outcome;
 * filesystem errors (missing directory, permission denied) propagate from
 * the underlying `readdirSync` call.
 */
export type DetectBinaryResult =
  | { kind: "ok"; path: string }
  | { kind: "none" }
  | { kind: "multiple"; candidates: string[] }

/**
 * Scan `challengeDir` and report executable-ELF candidates.
 *
 * Strategy:
 *   1. List immediate children (no recursion — CTF challenges are flat).
 *   2. Drop directories and files whose names look like shared objects.
 *   3. Require ELF magic + executable bit.
 *
 * Returns `{kind:"ok", path}` for exactly-one, `{kind:"none"}` for zero,
 * `{kind:"multiple", candidates}` for more than one (sorted).
 */
export function detectBinary(challengeDir: string): DetectBinaryResult {
  const entries = readdirSync(challengeDir, { withFileTypes: true })
  const candidates: string[] = []

  for (const entry of entries) {
    // Accept regular files and symlinks-to-files. CTFs occasionally ship the
    // target as a symlink (`chall -> chall.elf`); the downstream `isElf` /
    // `isExecutable` checks both follow symlinks via `statSync` / `openSync`.
    if (!entry.isFile() && !entry.isSymbolicLink()) {
      continue
    }
    if (looksLikeSharedObject(entry.name)) {
      continue
    }
    const path = join(challengeDir, entry.name)
    if (!isExecutable(path)) {
      continue
    }
    if (!isElf(path)) {
      continue
    }
    candidates.push(path)
  }

  if (candidates.length === 1) {
    return { kind: "ok", path: candidates[0]! }
  }
  if (candidates.length === 0) {
    return { kind: "none" }
  }
  candidates.sort()
  return { kind: "multiple", candidates }
}
