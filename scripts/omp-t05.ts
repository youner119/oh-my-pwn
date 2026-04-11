#!/usr/bin/env bun
/**
 * Manual T05 driver — load a challenge folder, run EnvSetup against real
 * docker, and dump everything the user needs to verify the M1 user-test
 * gate quality bar.
 *
 * Usage:
 *   bun scripts/omp-t05.ts <challenge-dir> [--binary <path>] [--dockerfile <path>] [--no-patch]
 *
 * Examples:
 *   bun scripts/omp-t05.ts ./benchmarks/lv1-stack-bof
 *   bun scripts/omp-t05.ts /tmp/chall --binary vuln
 *   bun scripts/omp-t05.ts ./challenge --binary deploy/chall --dockerfile deploy/Dockerfile
 *   bun scripts/omp-t05.ts ./challenge --dockerfile deploy/Dockerfile.prod
 *   bun scripts/omp-t05.ts ./challenge --no-patch         # skip patchelf step
 *
 * What it does:
 *   1. loadChallengeFolder (T03) — validates input contract, seeds .omp/.
 *      Pass --binary <name> to disambiguate when auto-detection fails.
 *   2. runEnvSetup (T04) — real docker build + libc/ld extract + glibc
 *      detect + journal append. Uses the live realDockerRunner.
 *   3. Prints a compact summary of the resulting state and points the user
 *      at the journal / state.json / artifacts on disk.
 *
 * Errors are caught and printed kind-first with the discriminated detail
 * fields, so the user can decide whether to retry, fix, or escalate.
 *
 * This script is the manual exercise driver for the M1 user-test gate.
 * It is not part of the production library and is not invoked from any
 * automated test.
 */

import { existsSync } from "node:fs"
import { resolve } from "node:path"
import {
  ChallengeLoadError,
  EnvSetupError,
  loadChallengeFolder,
  runEnvSetup,
} from "../src/features/omp"

interface CliArgs {
  challengeDir: string
  binary?: string
  dockerfile?: string
  noPatch: boolean
}

function parseArgs(argv: readonly string[]): CliArgs {
  const args = [...argv]
  let binary: string | undefined
  let dockerfile: string | undefined
  let noPatch = false
  let challengeDir: string | undefined

  while (args.length > 0) {
    const next = args.shift()!
    if (next === "--binary") {
      binary = args.shift()
      if (binary === undefined) {
        die("--binary requires a value")
      }
      continue
    }
    if (next === "--dockerfile") {
      dockerfile = args.shift()
      if (dockerfile === undefined) {
        die("--dockerfile requires a value")
      }
      continue
    }
    if (next === "--no-patch") {
      noPatch = true
      continue
    }
    if (next === "-h" || next === "--help") {
      printUsage()
      process.exit(0)
    }
    if (next.startsWith("--")) {
      die(`unknown flag: ${next}`)
    }
    if (challengeDir !== undefined) {
      die(`unexpected positional arg: ${next}`)
    }
    challengeDir = next
  }

  if (challengeDir === undefined) {
    printUsage()
    process.exit(1)
  }
  return { challengeDir, binary, dockerfile, noPatch }
}

function printUsage(): void {
  console.error(
    [
      "Usage: bun scripts/omp-t05.ts <challenge-dir> [--binary <path>] [--dockerfile <path>] [--no-patch]",
      "",
      "  <challenge-dir>     path to a CTF challenge folder.",
      "  --binary <path>     explicit binary location. Accepts a basename",
      "                      (`chall`), a relative path (`deploy/chall`),",
      "                      or an absolute path. Required when the binary",
      "                      lives in a subdirectory or auto-detection sees",
      "                      multiple candidates.",
      "  --dockerfile <path> explicit Dockerfile location. Same accepted",
      "                      forms as --binary. Required when the Dockerfile",
      "                      lives in a subdirectory like `deploy/Dockerfile`",
      "                      or has a non-standard name like `Dockerfile.prod`.",
      "                      When omitted, auto-detection looks for",
      "                      `Dockerfile`/`dockerfile` in the immediate",
      "                      children of <challenge-dir>.",
      "  --no-patch          skip the patchelf step that rewrites the binary's",
      "                      interpreter + rpath to use the docker image's",
      "                      libc/ld. Default is to patch (the original is",
      "                      backed up to `.omp/artifacts/<basename>.orig`).",
      "                      Pass --no-patch when you want to test the binary",
      "                      against the host's libc instead.",
      "",
      "Runs: loadChallengeFolder → runEnvSetup against real docker (+patchelf).",
      "",
      "Discovery note: T05 expects the human to know where the binary and",
      "Dockerfile live. Automatic discovery in messy nested CTF layouts is",
      "deferred to T18 — see `current-task.md` → 'Option A 결정사항'.",
    ].join("\n"),
  )
}

function die(msg: string): never {
  console.error(`error: ${msg}`)
  process.exit(2)
}

function main(): void {
  const { challengeDir, binary, dockerfile, noPatch } = parseArgs(
    process.argv.slice(2),
  )
  const absDir = resolve(challengeDir)

  if (!existsSync(absDir)) {
    die(`challenge dir not found: ${absDir}`)
  }

  console.log(`▶ challenge dir:   ${absDir}`)
  if (binary !== undefined) {
    console.log(`▶ binary hint:     ${binary}`)
  }
  if (dockerfile !== undefined) {
    console.log(`▶ dockerfile hint: ${dockerfile}`)
  }
  console.log(`▶ patch:           ${noPatch ? "disabled (--no-patch)" : "enabled"}`)

  const loaderOpts: { binary?: string; dockerfile?: string } = {}
  if (binary !== undefined) {
    loaderOpts.binary = binary
  }
  if (dockerfile !== undefined) {
    loaderOpts.dockerfile = dockerfile
  }

  console.log("")
  console.log("── Step 1: loadChallengeFolder ──")
  try {
    const loaded = loadChallengeFolder(absDir, loaderOpts)
    console.log(
      `  freshlyInitialized: ${loaded.freshlyInitialized}, shaDrift: ${loaded.shaDrift}`,
    )
    console.log(`  binary_path:   ${loaded.state.binary_path}`)
    console.log(`  binary_sha256: ${loaded.state.binary_sha256}`)
    console.log(`  dockerfile:    ${loaded.state.dockerfile_path}`)
    console.log(
      `  source:        ${loaded.state.source_present ? loaded.state.source_paths.join(", ") : "(none)"}`,
    )
  } catch (err) {
    handleLoaderError(err)
    process.exit(1)
  }

  console.log("")
  console.log("── Step 2: runEnvSetup (real docker + patchelf) ──")
  let result
  try {
    result = runEnvSetup(absDir, { patch: !noPatch })
  } catch (err) {
    handleEnvSetupError(err)
    process.exit(1)
  }

  console.log(
    `  rebuilt: ${result.rebuilt}, staticLinked: ${result.staticLinked}, patched: ${result.patched}`,
  )

  const state = result.state
  console.log("")
  console.log("── Result summary ──")
  console.log(`  docker_image:  ${state.docker_image ?? "(none)"}`)
  console.log(`  libc_version:  ${state.libc_version ?? "(none)"}`)
  console.log(`  libc_path:     ${state.libc_path ?? "(none)"}`)
  console.log(`  ld_path:       ${state.ld_path ?? "(none)"}`)
  if (state.binary_patched === true) {
    console.log("  binary patch:")
    console.log(`    original backup: ${state.binary_original_path}`)
    console.log(`    original sha256: ${state.binary_original_sha256}`)
    console.log(`    patched sha256:  ${state.binary_sha256}`)
    console.log("    → the binary at binary_path is now patched in place")
  } else {
    console.log("  binary patch:    (skipped or static)")
  }
  if (state.mitigations !== undefined) {
    console.log(`  mitigations:   ${state.mitigations.raw ?? ""}`)
    console.log(`    seccomp hint: ${state.mitigations.seccomp ?? false}`)
  }
  if (state.remote !== undefined) {
    console.log(
      `  remote:        ${state.remote.host}:${state.remote.port ?? "?"} ` +
        `wrapper=${state.remote.wrapper ?? "(none)"}`,
    )
    if (state.remote.command !== undefined) {
      console.log(`    command: ${state.remote.command}`)
    }
  }

  console.log("")
  console.log("── Inspect on disk ──")
  console.log(`  cat   ${absDir}/.omp/journal.md`)
  console.log(`  jq .  ${absDir}/.omp/state.json`)
  console.log(`  ls -la ${absDir}/.omp/artifacts/`)
  console.log(`  ls -la ${absDir}/.omp/logs/`)
}

function handleLoaderError(err: unknown): void {
  if (err instanceof ChallengeLoadError) {
    console.error(`  loader error [${err.kind}]: ${err.message}`)
    if (err.detail.kind === "ambiguous-binary") {
      console.error(`  reason: ${err.detail.reason}`)
      console.error(
        `  candidates (${err.detail.candidates.length}):`,
      )
      for (const c of err.detail.candidates) {
        console.error(`    - ${c}`)
      }
      console.error(
        "  → re-run with --binary <basename> to pick one explicitly",
      )
    }
    return
  }
  console.error("  loader threw a non-ChallengeLoadError:")
  console.error(err)
}

function handleEnvSetupError(err: unknown): void {
  if (err instanceof EnvSetupError) {
    console.error(`  envsetup error [${err.kind}]: ${err.message}`)
    switch (err.detail.kind) {
      case "docker-build-failed": {
        console.error(`  exitCode:     ${err.detail.exitCode}`)
        console.error(`  imageTag:     ${err.detail.imageTag}`)
        console.error(`  buildLogPath: ${err.detail.buildLogPath}`)
        console.error(`  → cat that log file for the full docker output`)
        break
      }
      case "libc-not-found": {
        console.error(`  imageTag: ${err.detail.imageTag}`)
        console.error(`  candidates tried (${err.detail.candidatesTried.length}):`)
        for (const c of err.detail.candidatesTried) {
          console.error(`    - ${c}`)
        }
        if (err.detail.imageListing !== undefined) {
          console.error("  image listing of /lib*:")
          for (const line of err.detail.imageListing.slice(0, 30)) {
            console.error(`    ${line}`)
          }
          if (err.detail.imageListing.length > 30) {
            console.error(
              `    ... (${err.detail.imageListing.length - 30} more lines)`,
            )
          }
        }
        break
      }
      case "extraction-failed": {
        console.error(`  exitCode: ${err.detail.exitCode}`)
        console.error(`  imagePath: ${err.detail.imagePath}`)
        console.error(`  stderr:`)
        console.error(err.detail.stderr)
        break
      }
      case "elf-parse-error": {
        console.error(`  binaryPath: ${err.detail.binaryPath}`)
        console.error(`  reason:     ${err.detail.reason}`)
        break
      }
      case "docker-not-available": {
        console.error(`  spawn code: ${err.detail.code ?? "(none)"}`)
        console.error(
          "  → make sure `docker` is in PATH and `docker ps` works for your user",
        )
        break
      }
      case "state-missing": {
        console.error(
          "  → loadChallengeFolder must run before runEnvSetup. This script does both, so something earlier went wrong.",
        )
        break
      }
      case "patchelf-not-available": {
        console.error(`  spawn code: ${err.detail.code ?? "(none)"}`)
        console.error(
          "  → install patchelf (`apt install patchelf` or `dnf install patchelf`)",
        )
        console.error("  → or pass --no-patch to skip the patch step")
        break
      }
      case "patchelf-failed": {
        console.error(`  binaryPath: ${err.detail.binaryPath}`)
        console.error(`  exitCode:   ${err.detail.exitCode}`)
        console.error(`  stderr:`)
        console.error(err.detail.stderr)
        console.error(
          "  → the original binary backup is preserved in .omp/artifacts/<basename>.orig",
        )
        break
      }
    }
    return
  }
  console.error("  envsetup threw a non-EnvSetupError:")
  console.error(err)
}

main()
