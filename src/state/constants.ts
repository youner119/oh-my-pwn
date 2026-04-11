/**
 * oh-my-pwn state layout constants.
 *
 * OmP persists per-challenge state inside each challenge folder under a
 * single `.omp/` directory (no global slug registry — see
 * .omc/specs/deep-interview-oh-my-pwn.md → "Post-interview refinements").
 */

/** Top-level OmP directory, relative to a challenge folder. */
export const OMP_DIR = ".omp"

/** Machine-truth structured state file (Zod-validated on load). */
export const STATE_FILE = "state.json"

/** Append-only human-readable progress log. */
export const JOURNAL_FILE = "journal.md"

/** Directory for exploit scripts produced by the Exploiter agent (T14). */
export const EXPLOIT_DIR = "exploit"

/** Directory for Verifier session logs (T15). */
export const LOGS_DIR = "logs"

/** Directory for loose artifacts (extracted libc/ld, Reverser dumps, etc.). */
export const ARTIFACTS_DIR = "artifacts"

/** Current ChallengeState schema version. Bump on breaking changes. */
export const CHALLENGE_STATE_SCHEMA_VERSION = "1"
