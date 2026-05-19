/**
 * T03 — challenge folder loader & validator.
 *
 * Single entry point: {@link loadChallengeFolder}. Given an absolute (or
 * relative) path to a CTF challenge folder, this function:
 *
 *   1. Validates the input contract — directory exists, contains a
 *      `Dockerfile`, and resolves to exactly one executable ELF binary
 *      (auto-detected, or pinned via the `binary` option).
 *   2. Computes the binary's SHA-256 so the loader and downstream agents can
 *      detect when the user swapped binaries between sessions.
 *   3. Detects optional C source files (`*.c`, `*.cc`, `*.cpp`, `*.cxx`) so
 *      Reverser (T07) can later short-circuit when source is present.
 *   4. Bootstraps `<challenge-dir>/.omp/{state.json, journal.md, exploit/,
 *      logs/, artifacts/}` via {@link initializeOmpDir}, which is itself
 *      idempotent and load-or-init.
 *   5. Records the binary SHA-256 into `state.json` on first init, or — on
 *      reload — compares it against the persisted value and appends a
 *      `## binary sha drift` section to `journal.md` if they diverge. The
 *      persisted state is **never** mutated by drift detection; only the
 *      journal records the divergence. Re-seeding is the user's job (via
 *      `rm -rf .omp/` or, post-T20, the prompt-driven correction protocol).
 *
 * Pre-work decisions for this task are recorded in
 * `.omc/state/current-task.md` → "T03 pre-work 결정 사항 (locked, 2026-04-11)".
 */

import { createHash } from "node:crypto"
import {
  existsSync,
  readFileSync,
  readdirSync,
  statSync,
} from "node:fs"
import { isAbsolute, join, resolve } from "node:path"
import {
  initializeOmpDir,
  saveChallengeState,
  getStatePaths,
} from "../state/io"
import { appendJournalSection } from "../state/journal"
import type { ChallengeState } from "../state/challenge-state"
import { ChallengeLoadError } from "./challenge-load-error"
import { detectBinary, isElf, isExecutable } from "./binary-detect"

/** Filenames the loader treats as the Dockerfile, in priority order. */
const DOCKERFILE_NAMES: readonly string[] = ["Dockerfile", "dockerfile"]

/** Lowercased extensions counted as C/C++ implementation source. */
const SOURCE_EXTENSIONS: readonly string[] = [".c", ".cc", ".cpp", ".cxx"]

export interface LoadChallengeFolderOptions {
  /**
   * Disambiguate the challenge binary when auto-detection cannot.
   *
   * Accepts a basename relative to `challengeDir` (preferred — matches what
   * an `AskUserQuestion` choice would produce), a relative path with sub-
   * directories (e.g. `deploy/chall`), or an absolute path. When supplied,
   * the loader skips auto-detection and validates this exact path is a
   * regular file, has the ELF magic, and has an executable bit.
   */
  binary?: string
  /**
   * Disambiguate the Dockerfile when it lives in a subdirectory like
   * `deploy/Dockerfile`, has a non-standard name, or shares a folder with
   * multiple Dockerfile variants.
   *
   * Accepts a basename relative to `challengeDir`, a relative path with
   * sub-directories (e.g. `deploy/Dockerfile`), or an absolute path. When
   * supplied, the loader skips auto-detection and validates this exact
   * path is a regular file. Auto-detection (looking for `Dockerfile` or
   * `dockerfile` in the immediate children of `challengeDir`) only runs
   * when this option is omitted.
   *
   * Per the T03 design, the loader is a pure library — discovery of the
   * right Dockerfile in messy CTF folder layouts is the **caller's**
   * responsibility. In M1 the caller is `omp-t05.ts` and the human passes
   * the path manually; from T18 onward an `omp-discoverer` LLM agent will
   * do the discovery as the Orchestrator's first sub-step (see
   * `current-task.md` → "Option A 결정사항").
   */
  dockerfile?: string
  /**
   * Absolute host path to the plugin's workspace mount source
   * (`<plugin-root>/workspace/`). When supplied, seeded into
   * `state.workspace_root` so downstream agents (Setup, Reverser, VH, SA,
   * Exploiter) can derive per-challenge container paths without inferring
   * the plugin root themselves. Plugin.ts wires `OMP_WORKSPACE_PATH` here.
   *
   * Added by spec `deep-interview-envsetup-agent.md` (T01.6).
   */
  workspaceRoot?: string
}

export interface LoadChallengeFolderResult {
  /** The persisted ChallengeState after loading or initializing. */
  state: ChallengeState
  /**
   * True if `state.json` did not exist before this call (i.e. the loader
   * just bootstrapped a new challenge). False on reload.
   */
  freshlyInitialized: boolean
  /**
   * True if the persisted `binary_sha256` did not match the current binary's
   * hash. The loader records the drift in `journal.md` but never mutates
   * `state.json`.
   */
  shaDrift: boolean
}

/**
 * Validate `<challengeDir>` against the input contract and bootstrap (or
 * reload) its `.omp/` state directory. See module doc for the full pipeline.
 *
 * @throws ChallengeLoadError on any input-contract violation.
 */
export function loadChallengeFolder(
  challengeDirInput: string,
  opts: LoadChallengeFolderOptions = {},
  now: Date = new Date(),
): LoadChallengeFolderResult {
  const challengeDir = resolve(challengeDirInput)

  if (!existsSync(challengeDir)) {
    throw new ChallengeLoadError({
      kind: "missing-dir",
      challengeDir,
      message: `Challenge directory not found: ${challengeDir}`,
    })
  }
  if (!statSync(challengeDir).isDirectory()) {
    throw new ChallengeLoadError({
      kind: "not-a-directory",
      challengeDir,
      message: `Path is not a directory: ${challengeDir}`,
    })
  }

  const dockerfilePath = resolveDockerfile(challengeDir, opts.dockerfile)
  if (dockerfilePath === null) {
    throw new ChallengeLoadError({
      kind: "missing-dockerfile",
      challengeDir,
      message:
        opts.dockerfile === undefined
          ? `Dockerfile not found in ${challengeDir}. ` +
            `OmP requires the challenge to ship its remote-server Dockerfile so EnvSetup (T04) can reproduce it locally. ` +
            `If the Dockerfile lives in a subdirectory (e.g. \`deploy/Dockerfile\`), pass it explicitly via the \`dockerfile\` option.`
          : `Dockerfile not found at the explicit path \`${opts.dockerfile}\` (resolved from ${challengeDir}).`,
    })
  }

  const binaryPath = resolveBinary(challengeDir, opts.binary)
  const binarySha256 = sha256OfFile(binaryPath)
  const sourcePaths = detectSourceFiles(challengeDir)
  const sourcePresent = sourcePaths.length > 0

  const { statePath } = getStatePaths(challengeDir)
  const freshlyInitialized = !existsSync(statePath)

  const seeded = initializeOmpDir(
    {
      challenge_dir: challengeDir,
      binary_path: binaryPath,
      dockerfile_path: dockerfilePath,
      source_present: sourcePresent,
      source_paths: sourcePaths,
      ...(opts.workspaceRoot !== undefined
        ? { workspace_root: opts.workspaceRoot }
        : {}),
    },
    now,
  )

  let state = seeded
  let shaDrift = false

  if (state.binary_sha256 === undefined) {
    // Either a fresh init or a partially-seeded state from an earlier crash;
    // either way, complete the seed by recording the SHA-256 and announce the
    // load in the journal.
    state = saveChallengeState({ ...state, binary_sha256: binarySha256 }, now)
    appendJournalSection(
      challengeDir,
      "challenge loaded",
      buildLoadedJournalBody({
        binaryPath,
        binarySha256,
        dockerfilePath,
        sourcePaths,
      }),
      now,
    )
  } else if (state.binary_sha256 !== binarySha256) {
    shaDrift = true
    appendJournalSection(
      challengeDir,
      "binary sha drift",
      buildDriftJournalBody({
        previous: state.binary_sha256,
        current: binarySha256,
        binaryPath,
      }),
      now,
    )
    // state preserved on purpose — see module doc.
  }
  // else: silent reload of an unchanged challenge. No journal noise.

  return { state, freshlyInitialized, shaDrift }
}

function resolveDockerfile(
  challengeDir: string,
  hint: string | undefined,
): string | null {
  if (hint !== undefined) {
    const path = isAbsolute(hint) ? hint : join(challengeDir, hint)
    if (!existsSync(path)) {
      return null
    }
    if (!statSync(path).isFile()) {
      return null
    }
    return path
  }
  // Auto-detect: only look at the immediate children. Discovery in nested
  // layouts (e.g. `deploy/Dockerfile`) is the caller's job — pass `dockerfile`
  // explicitly. See LoadChallengeFolderOptions.dockerfile docs.
  for (const name of DOCKERFILE_NAMES) {
    const candidate = join(challengeDir, name)
    if (existsSync(candidate) && statSync(candidate).isFile()) {
      return candidate
    }
  }
  return null
}

function resolveBinary(challengeDir: string, hint: string | undefined): string {
  if (hint === undefined) {
    return detectBinary(challengeDir)
  }

  const path = isAbsolute(hint) ? hint : join(challengeDir, hint)

  if (!existsSync(path)) {
    throw new ChallengeLoadError({
      kind: "missing-binary",
      challengeDir,
      binaryPath: path,
      message: `Binary not found at ${path}`,
    })
  }
  if (!statSync(path).isFile()) {
    throw new ChallengeLoadError({
      kind: "binary-not-elf",
      challengeDir,
      binaryPath: path,
      message: `Path is not a regular file: ${path}`,
    })
  }
  if (!isElf(path)) {
    throw new ChallengeLoadError({
      kind: "binary-not-elf",
      challengeDir,
      binaryPath: path,
      message: `File is not an ELF binary (missing 0x7F 'E' 'L' 'F' magic): ${path}`,
    })
  }
  if (!isExecutable(path)) {
    throw new ChallengeLoadError({
      kind: "binary-not-executable",
      challengeDir,
      binaryPath: path,
      message: `File has no execute bit set: ${path}. Run \`chmod +x\` and retry.`,
    })
  }
  return path
}

function detectSourceFiles(challengeDir: string): string[] {
  const entries = readdirSync(challengeDir, { withFileTypes: true })
  const sources: string[] = []
  for (const entry of entries) {
    // Accept symlinks-to-files for the same reason as detectBinary.
    if (!entry.isFile() && !entry.isSymbolicLink()) {
      continue
    }
    const lower = entry.name.toLowerCase()
    if (SOURCE_EXTENSIONS.some((ext) => lower.endsWith(ext))) {
      sources.push(join(challengeDir, entry.name))
    }
  }
  sources.sort()
  return sources
}

function sha256OfFile(path: string): string {
  const bytes = readFileSync(path)
  return createHash("sha256").update(bytes).digest("hex")
}

interface LoadedBody {
  binaryPath: string
  binarySha256: string
  dockerfilePath: string
  sourcePaths: string[]
}

function buildLoadedJournalBody(input: LoadedBody): string {
  const lines = [
    `- binary: \`${input.binaryPath}\``,
    `- binary sha256: \`${input.binarySha256}\``,
    `- Dockerfile: \`${input.dockerfilePath}\``,
    `- source present: ${input.sourcePaths.length > 0}`,
  ]
  if (input.sourcePaths.length > 0) {
    lines.push("- source files:")
    for (const p of input.sourcePaths) {
      lines.push(`  - \`${p}\``)
    }
  }
  return lines.join("\n")
}

interface DriftBody {
  previous: string
  current: string
  binaryPath: string
}

function buildDriftJournalBody(input: DriftBody): string {
  return [
    `- binary: \`${input.binaryPath}\``,
    `- previous sha256: \`${input.previous}\``,
    `- current sha256:  \`${input.current}\``,
    "- action: state.json preserved (loader is non-mutating). To re-seed, run `rm -rf .omp/` and reload, or use the T20 prompt correction protocol once available.",
  ].join("\n")
}
