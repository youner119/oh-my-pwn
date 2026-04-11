/**
 * Binary detection helpers used by {@link ./load-challenge-folder}.
 *
 * Two responsibilities:
 *
 * - {@link isElf} / {@link isExecutable} — cheap filesystem-level predicates
 *   that the loader uses both for auto-detection and for validating an
 *   explicit `{ binary }` hint.
 * - {@link detectBinary} — pick exactly one challenge binary out of a folder
 *   by reading the first 4 bytes of every regular file, filtering libc/ld
 *   share-objects out, and requiring the executable bit. Throws a typed
 *   {@link ChallengeLoadError} (`kind: "ambiguous-binary"`) when the result
 *   is anything other than exactly one candidate, so the caller can re-run
 *   the loader with an explicit `{ binary }` after disambiguating with the
 *   user.
 *
 * No I/O outside of `node:fs` synchronous calls — matches T02's I/O style and
 * keeps the loader callable from OmO hook tiers without async plumbing.
 */

import {
  closeSync,
  openSync,
  readSync,
  readdirSync,
  statSync,
} from "node:fs"
import { join } from "node:path"
import { ChallengeLoadError } from "./challenge-load-error"

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
 * Auto-detect the single executable ELF binary in `challengeDir`.
 *
 * Strategy:
 *   1. List immediate children (no recursion — CTF challenges are flat).
 *   2. Drop directories and files whose names look like shared objects.
 *   3. Require ELF magic + executable bit.
 *   4. If exactly one survives, return its absolute path.
 *   5. Otherwise throw a typed `ambiguous-binary` error so the caller can
 *      ask the user which file to use.
 *
 * @throws ChallengeLoadError when 0 or >1 candidates remain.
 */
export function detectBinary(challengeDir: string): string {
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
    return candidates[0]!
  }

  if (candidates.length === 0) {
    throw new ChallengeLoadError({
      kind: "ambiguous-binary",
      challengeDir,
      reason: "none",
      candidates: [],
      message:
        `No executable ELF binary found in ${challengeDir}. ` +
        `Pass { binary: "<filename>" } to loadChallengeFolder to specify it explicitly.`,
    })
  }

  candidates.sort()
  const names = candidates.map((p) => p.split("/").pop()).join(", ")
  throw new ChallengeLoadError({
    kind: "ambiguous-binary",
    challengeDir,
    reason: "multiple",
    candidates,
    message:
      `Multiple executable ELF binaries in ${challengeDir}: ${names}. ` +
      `Pass { binary: "<filename>" } to loadChallengeFolder to disambiguate.`,
  })
}
