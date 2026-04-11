/**
 * T04 — high-level EnvSetup pipeline.
 *
 * `runEnvSetup` orchestrates the deterministic chain that turns a
 * "challenge folder with binary + Dockerfile" (post-T03) into a fully
 * populated `ChallengeState` with mitigations, libc/ld artefacts, glibc
 * version, docker image, and remote entrypoint metadata, plus a journal
 * entry summarising what was learned.
 *
 * Pipeline (in execution order):
 *
 *   1. Load `state.json` (must exist — T03 is a prerequisite).
 *   2. ELF mitigations on the binary (no docker required).
 *   3. Dockerfile parse → remote + seccomp hint.
 *   4. Save partial state so progress survives subsequent failures.
 *   5. `docker build` (cache-aware).
 *   6. `docker create` + `docker cp` libc/ld out of the image.
 *   6.5. `patchelf --set-interpreter --set-rpath` (skipped for static
 *        binaries or when `opts.patch === false`). Backs up the original
 *        to `<.omp/artifacts/{basename}.orig>` so re-runs are idempotent.
 *   7. glibc version detect on the extracted libc.
 *   8. Final `saveChallengeState` + `appendJournalSection("envsetup", ...)`.
 *
 * Failure semantics: every step is wrapped so that, if a later step
 * throws, the partial progress from earlier steps is still committed to
 * `state.json`. We then append `## envsetup failed at <step>` to the
 * journal and re-throw the original error so the caller (assistant in M1,
 * Orchestrator agent in T18) sees the full type and can react.
 *
 * Per the T04 pre-work decision (`current-task.md`), this module returns
 * a result struct rather than mutating shared globals so a future LLM
 * agent wrapping this library can call it as one big step OR drop down
 * to the individual building blocks (`parseDockerfile`, `parseElfMitigations`,
 * `dockerBuildImage`, `extractLibcAndLd`, `detectGlibcVersion`) for finer
 * control.
 */

import { basename, join } from "node:path"
import { saveChallengeState, loadChallengeState } from "../state/io"
import { resolveArtifactsDir } from "../state/layout"
import { appendJournalSection } from "../state/journal"
import type {
  ChallengeState,
  Mitigations,
  RemoteEntrypoint,
} from "../state/challenge-state"
import { dockerBuildImage } from "./docker-build"
import { extractLibcAndLd } from "./docker-extract"
import { detectGlibcVersion } from "./glibc-detect"
import { parseDockerfile } from "./dockerfile-parse"
import {
  ElfParseError,
  parseElfMitigations,
  type ElfMitigations,
} from "./elf-mitigations"
import { realDockerRunner, type DockerRunner } from "./docker-runner"
import { EnvSetupError } from "./envsetup-error"
import { patchBinaryInterpreter, type SpawnFn } from "./patch-elf"

export interface RunEnvSetupResult {
  state: ChallengeState
  /** True if `docker build` ran (vs reusing the cached image). */
  rebuilt: boolean
  /** True if the binary was determined to be statically linked. */
  staticLinked: boolean
  /**
   * True iff step 6.5 ran patchelf and the binary at `state.binary_path`
   * is now pointing at the docker image's libc/ld. False if the binary
   * was static, the user passed `patch: false`, or the patch step was
   * skipped because libc/ld extraction did not produce both files.
   */
  patched: boolean
}

export interface RunEnvSetupOptions {
  /** Override the docker runner — tests inject a fake. */
  runner?: DockerRunner
  /** Override the current time, for deterministic timestamps in tests. */
  now?: Date
  /**
   * Whether to run `patchelf --set-interpreter --set-rpath` against the
   * binary after libc/ld are extracted. Default: `true`. Pass `false` to
   * skip the patch step (e.g. for testing the binary's original behaviour
   * against the host's libc).
   */
  patch?: boolean
  /**
   * Inject a fake subprocess runner for the patchelf step. Default uses
   * `node:child_process.spawnSync`. Tests use this so they can exercise
   * the patch path without `patchelf` actually present.
   */
  spawn?: SpawnFn
}

/**
 * Run the full EnvSetup pipeline against an already-loaded challenge.
 *
 * @throws EnvSetupError on any recoverable pipeline failure. Partial
 *         progress (mitigations, dockerfile-parsed remote, etc.) is
 *         persisted to `state.json` before the throw, and the journal
 *         records `## envsetup failed at <step>`.
 */
export function runEnvSetup(
  challengeDir: string,
  opts: RunEnvSetupOptions = {},
): RunEnvSetupResult {
  const runner = opts.runner ?? realDockerRunner
  const now = opts.now ?? new Date()

  let state = loadChallengeState(challengeDir)
  if (state === null) {
    throw new EnvSetupError({
      kind: "state-missing",
      challengeDir,
      message: `No state.json at ${challengeDir}/.omp/. Run loadChallengeFolder (T03) before EnvSetup.`,
    })
  }

  // Step 2: ELF mitigations.
  let mitigations: ElfMitigations
  try {
    mitigations = parseElfMitigations(state.binary_path)
  } catch (cause) {
    if (cause instanceof ElfParseError) {
      recordFailure(challengeDir, state, "elf-mitigations", cause.message, now)
      throw new EnvSetupError({
        kind: "elf-parse-error",
        challengeDir,
        binaryPath: cause.binaryPath,
        reason: cause.reason,
        message: cause.message,
      })
    }
    throw cause
  }

  // Step 3: Dockerfile parse (lenient — never throws).
  const parsedDockerfile = parseDockerfile(state.dockerfile_path)
  const remote = buildRemoteEntrypoint(parsedDockerfile)
  const mitigationsWithSeccomp: Mitigations = {
    nx: mitigations.nx,
    pie: mitigations.pie,
    canary: mitigations.canary,
    relro: mitigations.relro,
    seccomp: parsedDockerfile.hasSeccompFlag,
    raw: mitigations.raw,
  }

  // Step 4: Partial commit so step 5+ failures don't lose what we already learned.
  state = saveChallengeState(
    {
      ...state,
      mitigations: mitigationsWithSeccomp,
      remote,
    },
    now,
  )

  // Step 5: docker build.
  let buildResult
  try {
    buildResult = dockerBuildImage(state, runner, { now })
  } catch (cause) {
    recordFailure(
      challengeDir,
      state,
      "docker-build",
      (cause as Error).message,
      now,
    )
    throw cause
  }
  state = saveChallengeState(
    { ...state, docker_image: buildResult.imageTag },
    now,
  )

  // Step 6: extract libc / ld.
  const artifactsDir = resolveArtifactsDir(challengeDir)
  let extractResult
  try {
    extractResult = extractLibcAndLd(
      {
        imageTag: buildResult.imageTag,
        binaryPath: state.binary_path,
        artifactsDir,
        challengeDir,
      },
      runner,
    )
  } catch (cause) {
    recordFailure(
      challengeDir,
      state,
      "docker-extract",
      (cause as Error).message,
      now,
    )
    throw cause
  }

  let libcVersion: string
  let staticLinked: boolean
  let patched = false
  if (extractResult.staticLinked === true) {
    staticLinked = true
    libcVersion = "static"
    state = saveChallengeState(
      {
        ...state,
        libc_version: libcVersion,
        libc_path: undefined,
        ld_path: undefined,
      },
      now,
    )
  } else {
    staticLinked = false
    // Step 7: glibc version detect on the extracted libc.
    const detected = detectGlibcVersion(extractResult.libcPath)
    libcVersion = detected ?? "unknown"
    state = saveChallengeState(
      {
        ...state,
        libc_version: libcVersion,
        libc_path: extractResult.libcPath,
        ld_path: extractResult.ldPath,
      },
      now,
    )

    // Step 6.5: patch the binary's interpreter + rpath so it loads the
    // docker image's libc/ld. Skipped when `opts.patch === false` or when
    // the extractor did not return an ld path (we need an interpreter to
    // set; rpath alone is not enough).
    const wantPatch = opts.patch !== false
    if (wantPatch && extractResult.ldPath !== undefined) {
      const backupPath = join(
        artifactsDir,
        `${basename(state.binary_path)}.orig`,
      )
      try {
        const patchResult = patchBinaryInterpreter(
          {
            binaryPath: state.binary_path,
            backupPath,
            interpreterPath: extractResult.ldPath,
            libcDir: artifactsDir,
            challengeDir,
          },
          { spawn: opts.spawn },
        )
        state = saveChallengeState(
          {
            ...state,
            binary_patched: true,
            binary_original_path: backupPath,
            // Preserve the original sha as the input contract identity.
            // If a previous run already recorded one, do NOT overwrite it
            // (the backup is canonical) — but on first patch, the
            // pre-patch sha is what's currently in `binary_sha256`.
            binary_original_sha256:
              state.binary_original_sha256 ?? patchResult.originalSha256,
            binary_sha256: patchResult.patchedSha256,
          },
          now,
        )
        patched = true
      } catch (cause) {
        recordFailure(
          challengeDir,
          state,
          "patchelf",
          (cause as Error).message,
          now,
        )
        throw cause
      }
    }
  }

  // Step 8: final journal entry.
  appendJournalSection(
    challengeDir,
    "envsetup",
    buildEnvSetupJournalBody({
      state,
      cached: buildResult.cached,
      buildLogPath: buildResult.buildLogPath,
      staticLinked,
      patched,
    }),
    now,
  )

  return {
    state,
    rebuilt: !buildResult.cached,
    staticLinked,
    patched,
  }
}

/* ── Helpers ────────────────────────────────────────────────────────────── */

function buildRemoteEntrypoint(
  parsed: ReturnType<typeof parseDockerfile>,
): RemoteEntrypoint | undefined {
  if (
    parsed.exposedPorts.length === 0 &&
    parsed.wrapper === undefined &&
    parsed.cmd === undefined &&
    parsed.entrypoint === undefined
  ) {
    return undefined
  }
  return {
    host: "127.0.0.1",
    port: parsed.exposedPorts[0],
    wrapper: parsed.wrapper,
    command: parsed.entrypoint ?? parsed.cmd,
  }
}

function recordFailure(
  challengeDir: string,
  state: ChallengeState,
  step: string,
  reason: string,
  now: Date,
): void {
  // Persist whatever we have (re-save state to bump updated_at and lock the
  // partial fields), then drop a journal breadcrumb so the human / future
  // agent can see exactly where the pipeline died.
  try {
    saveChallengeState(state, now)
  } catch {
    // ignore — we're already in an error path
  }
  try {
    appendJournalSection(
      challengeDir,
      `envsetup failed at ${step}`,
      `- step: ${step}\n- reason: ${sanitizeReason(reason)}`,
      now,
    )
  } catch {
    // ignore — we're already in an error path
  }
}

/**
 * Collapse multi-line / oversized error messages into a single short line so
 * they fit cleanly inside the journal's bullet-list breadcrumb. Long docker
 * stderr blobs are referenced from the EnvSetupError detail (e.g. via
 * `buildLogPath`) — the journal only needs the headline.
 */
function sanitizeReason(reason: string): string {
  const collapsed = reason.replace(/\s+/gu, " ").trim()
  if (collapsed.length <= 500) {
    return collapsed
  }
  return `${collapsed.slice(0, 497)}...`
}

interface JournalBodyInputs {
  state: ChallengeState
  cached: boolean
  buildLogPath: string | undefined
  staticLinked: boolean
  patched: boolean
}

function buildEnvSetupJournalBody(input: JournalBodyInputs): string {
  const { state, cached, buildLogPath, staticLinked, patched } = input
  const lines: string[] = []

  lines.push("### Mitigations")
  if (state.mitigations !== undefined) {
    lines.push(`- raw: \`${state.mitigations.raw ?? ""}\``)
    lines.push(`- nx: ${state.mitigations.nx ?? "unknown"}`)
    lines.push(`- pie: ${state.mitigations.pie ?? "unknown"}`)
    lines.push(`- canary: ${state.mitigations.canary ?? "unknown"}`)
    lines.push(`- relro: ${state.mitigations.relro ?? "unknown"}`)
    lines.push(`- seccomp (hint): ${state.mitigations.seccomp ?? false}`)
  }

  lines.push("")
  lines.push("### libc / ld")
  if (staticLinked) {
    lines.push("- statically linked binary — no libc/ld extraction performed")
  } else {
    lines.push(`- libc_version: ${state.libc_version ?? "unknown"}`)
    lines.push(`- libc_path: \`${state.libc_path ?? "<none>"}\``)
    lines.push(`- ld_path: \`${state.ld_path ?? "<none>"}\``)
  }

  lines.push("")
  lines.push("### Binary patch (patchelf)")
  if (patched) {
    lines.push("- patched: true (set-interpreter + set-rpath applied this run)")
    lines.push(`- original backup: \`${state.binary_original_path ?? "<none>"}\``)
    lines.push(`- original sha256: \`${state.binary_original_sha256 ?? "<none>"}\``)
    lines.push(`- patched sha256:  \`${state.binary_sha256 ?? "<none>"}\``)
  } else if (staticLinked) {
    lines.push("- patched: false (skipped — statically linked binary)")
  } else if (state.binary_patched === true) {
    // The binary on disk is still patched from a previous run, but this
    // run did not re-run patchelf (likely --no-patch was passed).
    lines.push(
      "- patched: skipped this run, but state.binary_patched=true (binary on disk was patched in a previous run)",
    )
    lines.push(`- original backup: \`${state.binary_original_path ?? "<none>"}\``)
  } else {
    lines.push("- patched: false (skipped — patch=false or ld not extracted)")
  }

  lines.push("")
  lines.push("### Docker image")
  lines.push(`- image: \`${state.docker_image ?? "<none>"}\``)
  lines.push(`- cached: ${cached}`)
  if (buildLogPath !== undefined) {
    lines.push(`- build log: \`${buildLogPath}\``)
  }

  lines.push("")
  lines.push("### Remote entrypoint")
  if (state.remote === undefined) {
    lines.push("- (none — Dockerfile did not declare EXPOSE / CMD / ENTRYPOINT)")
  } else {
    lines.push(`- host: ${state.remote.host}`)
    lines.push(`- port: ${state.remote.port ?? "<unknown>"}`)
    lines.push(`- wrapper: ${state.remote.wrapper ?? "<none>"}`)
    lines.push(`- command: \`${state.remote.command ?? "<none>"}\``)
  }

  return lines.join("\n")
}
