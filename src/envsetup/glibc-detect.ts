/**
 * Best-effort glibc version detection from a libc binary on disk.
 *
 * Strategy: scan the libc bytes for the GNU C Library banner string. Every
 * glibc release embeds a "GNU C Library ... release version 2.XX" string
 * (and has done since at least glibc 2.0), so a single regex over the file
 * contents is enough to identify the major.minor version.
 *
 * Why not run `<libc> --version`? Because that requires *executing* the
 * libc, which depends on having a matching ld-linux on the host and is
 * generally fragile across architectures. Reading bytes is portable.
 *
 * Returns `null` for non-glibc libcs (musl, uClibc, bionic) — the caller
 * (`run-envsetup.ts`) writes "version unknown" to the journal in that
 * case rather than treating it as an error. Per the T04 pre-work decision
 * this is **not** an error condition.
 */

import { readFileSync } from "node:fs"

/**
 * Inspect a libc binary and return its glibc version (e.g. "2.31"), or
 * `null` if the file is not glibc / the banner could not be located.
 *
 * Returns `null` rather than throwing on read failure too — the calling
 * pipeline already validated the file exists at extraction time, so a
 * read failure here is exotic and best handled as "unknown".
 */
export function detectGlibcVersion(libcPath: string): string | null {
  let bytes: Buffer
  try {
    bytes = readFileSync(libcPath)
  } catch {
    return null
  }
  return detectGlibcVersionFromBytes(bytes)
}

/**
 * Pure-bytes variant exposed for unit tests so they can pass synthetic
 * banner buffers without writing to disk.
 */
export function detectGlibcVersionFromBytes(bytes: Buffer): string | null {
  // The banner format is stable across releases:
  //
  //   "GNU C Library (GNU libc) stable release version 2.31."
  //   "GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.4) stable release version 2.35."
  //
  // We anchor on the trailing "release version 2.X[Y][.Z]" so distro
  // re-tagging in the parenthesised prefix does not confuse us. The
  // optional patch level (e.g. 2.31.1) is captured.
  const text = bytes.toString("binary")
  const match = text.match(/release version (\d+\.\d+(?:\.\d+)?)/u)
  if (match === null) {
    return null
  }
  return match[1]!
}
