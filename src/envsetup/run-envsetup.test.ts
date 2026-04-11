import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { loadChallengeFolder } from "../loader/load-challenge-folder"
import { loadChallengeState } from "../state/io"
import { resolveJournalPath } from "../state/layout"
import { runEnvSetup } from "./run-envsetup"
import { EnvSetupError } from "./envsetup-error"
import type { SpawnFn } from "./patch-elf"
import { FakeDockerRunner, dockerEnoentError } from "./fake-docker-runner"
import {
  buildElfFixture,
  TEST_DT_BIND_NOW,
  TEST_PF_R,
  TEST_PF_W,
  TEST_PT_DYNAMIC,
  TEST_PT_GNU_RELRO,
  TEST_PT_GNU_STACK,
  TEST_PT_INTERP,
  TEST_PT_LOAD,
} from "./elf-test-fixtures"

const FAKE_CONTAINER_ID = "abc123def456"

function makeChallengeDir(label: string): string {
  const dir = join(
    tmpdir(),
    `omp-runenv-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  )
  mkdirSync(dir, { recursive: true })
  return dir
}

function seedDynamicChallenge(dir: string): void {
  // Hardened dynamic ELF: NX on, PIE on, RELRO full, no canary symbol.
  const elf = buildElfFixture({
    type: "dyn",
    programHeaders: [
      { type: TEST_PT_INTERP },
      { type: TEST_PT_LOAD, flags: TEST_PF_R },
      { type: TEST_PT_GNU_STACK, flags: TEST_PF_R | TEST_PF_W },
      { type: TEST_PT_GNU_RELRO },
      { type: TEST_PT_DYNAMIC, pointsAtDynamic: true },
    ],
    dynamic: [{ tag: TEST_DT_BIND_NOW, val: 0 }],
  })
  const binPath = join(dir, "chall")
  writeFileSync(binPath, elf)
  chmodSync(binPath, 0o755)
  writeFileSync(
    join(dir, "Dockerfile"),
    `FROM ubuntu:22.04\nCOPY chall /chall\nEXPOSE 1337\nCMD ["ynetd", "-p", "1337", "/chall"]\n`,
  )
}

function seedStaticChallenge(dir: string): void {
  // Static ELF: no PT_INTERP, no canary, RELRO none, NX off.
  const elf = buildElfFixture({
    type: "exec",
    programHeaders: [{ type: TEST_PT_LOAD, flags: TEST_PF_R }],
  })
  const binPath = join(dir, "chall")
  writeFileSync(binPath, elf)
  chmodSync(binPath, 0o755)
  writeFileSync(
    join(dir, "Dockerfile"),
    `FROM alpine\nCOPY chall /chall\nEXPOSE 4242\nCMD ["/chall"]\n`,
  )
}

interface FakeImageContents {
  libcContent?: string
  ldContent?: string
}

/**
 * Fake patchelf spawn that records every invocation and (optionally)
 * appends a marker to the binary so the test can prove the binary was
 * actually rewritten. The default succeeds with no body change.
 */
interface FakePatchelf {
  spawn: SpawnFn
  calls: Array<{ args: readonly string[] }>
}

function fakePatchelf(opts: {
  failExitCode?: number
  failStderr?: string
  rewrite?: (binaryPath: string) => void
  enoent?: boolean
} = {}): FakePatchelf {
  const calls: Array<{ args: readonly string[] }> = []
  const spawn: SpawnFn = (_cmd, args) => {
    calls.push({ args })
    if (opts.enoent === true) {
      const err = Object.assign(new Error("spawnSync patchelf ENOENT"), {
        code: "ENOENT",
      })
      throw err
    }
    if (opts.failExitCode !== undefined) {
      return {
        exitCode: opts.failExitCode,
        stdout: Buffer.alloc(0),
        stderr: Buffer.from(opts.failStderr ?? "patchelf failed\n", "utf-8"),
      }
    }
    if (opts.rewrite !== undefined) {
      // Find the binary path argument (last positional).
      const binaryPath = args[args.length - 1]!
      opts.rewrite(binaryPath)
    }
    return { exitCode: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }
  }
  return { spawn, calls }
}

function fakeImageRunner(contents: FakeImageContents): FakeDockerRunner {
  return new FakeDockerRunner((call) => {
    if (call.args[0] === "build") {
      return { exitCode: 0, stdout: "Successfully tagged ...\n" }
    }
    if (call.args[0] === "image" && call.args[1] === "inspect") {
      return { exitCode: 1, stderr: "no such image\n" }
    }
    if (call.args[0] === "create") {
      return { exitCode: 0, stdout: `${FAKE_CONTAINER_ID}\n` }
    }
    if (call.args[0] === "cp") {
      const src = call.args[2]!
      const dest = call.args[3]!
      if (
        src.includes("/lib/x86_64-linux-gnu/libc.so.6") &&
        contents.libcContent !== undefined
      ) {
        writeFileSync(dest, contents.libcContent)
        return { exitCode: 0 }
      }
      if (
        src.includes("/lib64/ld-linux-x86-64.so.2") &&
        contents.ldContent !== undefined
      ) {
        writeFileSync(dest, contents.ldContent)
        return { exitCode: 0 }
      }
      return { exitCode: 1, stderr: "not present\n" }
    }
    if (call.args[0] === "run") {
      // Listing probe — used only on libc-not-found error path.
      return { exitCode: 0, stdout: "/lib:\nbusybox\n" }
    }
    if (call.args[0] === "rm") {
      return { exitCode: 0 }
    }
    throw new Error(`unexpected docker call: ${call.args.join(" ")}`)
  })
}

describe("runEnvSetup — end to end with fake docker", () => {
  let dir: string

  beforeEach(() => {
    dir = makeChallengeDir("e2e")
  })

  afterEach(() => {
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test("dynamic challenge: full pipeline fills mitigations + libc + remote + patch + journal", () => {
    seedDynamicChallenge(dir)
    loadChallengeFolder(dir) // T03 prerequisite

    const runner = fakeImageRunner({
      libcContent:
        "GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3) stable release version 2.35.\n",
      ldContent: "fake ld bytes\n",
    })

    // Fake patchelf that appends a marker to the binary so we can prove
    // the file was rewritten.
    const patchelf = fakePatchelf({
      rewrite: (binaryPath) => {
        const original = readFileSync(binaryPath)
        writeFileSync(
          binaryPath,
          Buffer.concat([original, Buffer.from("PATCHED")]),
        )
      },
    })

    const result = runEnvSetup(dir, {
      runner,
      spawn: patchelf.spawn,
      now: new Date("2026-04-11T13:00:00.000Z"),
    })

    expect(result.staticLinked).toBe(false)
    expect(result.rebuilt).toBe(true)
    expect(result.patched).toBe(true)

    const persisted = loadChallengeState(dir)!

    // Mitigations populated.
    expect(persisted.mitigations).toBeDefined()
    expect(persisted.mitigations!.nx).toBe(true)
    expect(persisted.mitigations!.pie).toBe(true)
    expect(persisted.mitigations!.relro).toBe("full")
    expect(persisted.mitigations!.canary).toBe(false)
    expect(persisted.mitigations!.seccomp).toBe(false)

    // libc / ld extracted.
    expect(persisted.libc_version).toBe("2.35")
    expect(persisted.libc_path).toBeDefined()
    expect(existsSync(persisted.libc_path!)).toBe(true)
    expect(persisted.ld_path).toBeDefined()
    expect(existsSync(persisted.ld_path!)).toBe(true)

    // Docker image tag follows the omp-<sha8> convention.
    expect(persisted.docker_image).toMatch(/^omp-[0-9a-f]{8}$/u)

    // Remote entrypoint extracted from Dockerfile.
    expect(persisted.remote).toBeDefined()
    expect(persisted.remote!.host).toBe("127.0.0.1")
    expect(persisted.remote!.port).toBe(1337)
    expect(persisted.remote!.wrapper).toBe("ynetd")

    // Patch step ran with the right args.
    expect(patchelf.calls.length).toBe(1)
    expect(patchelf.calls[0]!.args[0]).toBe("--set-interpreter")
    expect(patchelf.calls[0]!.args[1]).toBe(persisted.ld_path!)
    expect(patchelf.calls[0]!.args[2]).toBe("--set-rpath")

    // State now records the patch and the original backup.
    expect(persisted.binary_patched).toBe(true)
    expect(persisted.binary_original_path).toBeDefined()
    expect(existsSync(persisted.binary_original_path!)).toBe(true)
    expect(persisted.binary_original_sha256).toBeDefined()
    // After patch, binary_sha256 should differ from the original sha.
    expect(persisted.binary_sha256).not.toBe(persisted.binary_original_sha256)

    // The on-disk binary actually contains the appended marker.
    expect(readFileSync(persisted.binary_path).toString("utf-8")).toContain(
      "PATCHED",
    )

    // Journal section appended.
    const journal = readFileSync(resolveJournalPath(dir), "utf-8")
    expect(journal).toContain("## envsetup")
    expect(journal).toContain("libc_version: 2.35")
    expect(journal).toContain("nx: true")
    expect(journal).toContain("port: 1337")
    expect(journal).toContain("Binary patch")
    expect(journal).toContain("patched: true")
  })

  test("dynamic challenge with patch=false: skips patchelf, leaves binary untouched", () => {
    seedDynamicChallenge(dir)
    loadChallengeFolder(dir)
    const originalBytes = readFileSync(join(dir, "chall"))

    const runner = fakeImageRunner({
      libcContent:
        "GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9) stable release version 2.31.\n",
      ldContent: "fake ld\n",
    })
    const patchelf = fakePatchelf() // would succeed, but should not be called

    const result = runEnvSetup(dir, {
      runner,
      spawn: patchelf.spawn,
      patch: false,
    })

    expect(result.patched).toBe(false)
    expect(patchelf.calls.length).toBe(0)
    // Binary on disk is untouched.
    expect(readFileSync(join(dir, "chall"))).toEqual(originalBytes)

    const persisted = loadChallengeState(dir)!
    expect(persisted.binary_patched).toBeUndefined()
    expect(persisted.binary_original_path).toBeUndefined()

    const journal = readFileSync(resolveJournalPath(dir), "utf-8")
    expect(journal).toContain("patched: false")
    expect(journal).toContain("patch=false or ld not extracted")
  })

  test("static challenge: marks libc_version=static, skips libc extraction AND patch, no error", () => {
    seedStaticChallenge(dir)
    loadChallengeFolder(dir)

    const runner = fakeImageRunner({}) // No libc available in image.
    const patchelf = fakePatchelf() // should not be called

    const result = runEnvSetup(dir, { runner, spawn: patchelf.spawn })

    expect(result.staticLinked).toBe(true)
    expect(result.patched).toBe(false)
    expect(patchelf.calls.length).toBe(0)

    const persisted = loadChallengeState(dir)!
    expect(persisted.libc_version).toBe("static")
    expect(persisted.libc_path).toBeUndefined()
    expect(persisted.ld_path).toBeUndefined()
    expect(persisted.binary_patched).toBeUndefined()
    expect(persisted.mitigations).toBeDefined() // still populated

    const journal = readFileSync(resolveJournalPath(dir), "utf-8")
    expect(journal).toContain("statically linked binary")
    expect(journal).toContain("skipped — statically linked")
  })

  test("patchelf failure: partial state (mitigations/libc/docker) preserved + breadcrumb", () => {
    seedDynamicChallenge(dir)
    loadChallengeFolder(dir)

    const runner = fakeImageRunner({
      libcContent:
        "GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9) stable release version 2.31.\n",
      ldContent: "fake ld\n",
    })
    const patchelf = fakePatchelf({
      failExitCode: 1,
      failStderr: "patchelf: cannot find section .interp\n",
    })

    try {
      runEnvSetup(dir, { runner, spawn: patchelf.spawn })
      throw new Error("expected throw")
    } catch (err) {
      expect(err).toBeInstanceOf(EnvSetupError)
      expect((err as EnvSetupError).kind).toBe("patchelf-failed")
    }

    // Everything that ran before patchelf is still committed.
    const persisted = loadChallengeState(dir)!
    expect(persisted.mitigations).toBeDefined()
    expect(persisted.docker_image).toBeDefined()
    expect(persisted.libc_path).toBeDefined()
    expect(persisted.libc_version).toBe("2.31")
    expect(persisted.binary_patched).toBeUndefined() // patch never landed

    // Backup exists even on failure (created BEFORE patchelf was invoked).
    const backupPath = join(dir, ".omp", "artifacts", "chall.orig")
    expect(existsSync(backupPath)).toBe(true)

    const journal = readFileSync(resolveJournalPath(dir), "utf-8")
    expect(journal).toContain("envsetup failed at patchelf")
  })

  test("patchelf not installed (ENOENT): translates to patchelf-not-available", () => {
    seedDynamicChallenge(dir)
    loadChallengeFolder(dir)

    const runner = fakeImageRunner({
      libcContent:
        "GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9) stable release version 2.31.\n",
      ldContent: "fake ld\n",
    })
    const patchelf = fakePatchelf({ enoent: true })

    try {
      runEnvSetup(dir, { runner, spawn: patchelf.spawn })
      throw new Error("expected throw")
    } catch (err) {
      expect(err).toBeInstanceOf(EnvSetupError)
      expect((err as EnvSetupError).kind).toBe("patchelf-not-available")
    }
  })

  test("dynamic but no libc in image → libc-not-found, partial state preserved", () => {
    seedDynamicChallenge(dir)
    loadChallengeFolder(dir)

    const runner = fakeImageRunner({}) // dynamic ELF + image with no libc
    try {
      runEnvSetup(dir, { runner })
      throw new Error("expected throw")
    } catch (err) {
      expect(err).toBeInstanceOf(EnvSetupError)
      expect((err as EnvSetupError).kind).toBe("libc-not-found")
    }

    // Mitigations + remote + docker_image were committed before the failure.
    const persisted = loadChallengeState(dir)!
    expect(persisted.mitigations).toBeDefined()
    expect(persisted.docker_image).toBeDefined()
    expect(persisted.remote).toBeDefined()

    // Failure breadcrumb in journal.
    const journal = readFileSync(resolveJournalPath(dir), "utf-8")
    expect(journal).toContain("envsetup failed at docker-extract")
  })

  test("docker missing → docker-not-available; mitigations still committed", () => {
    seedDynamicChallenge(dir)
    loadChallengeFolder(dir)

    const runner = new FakeDockerRunner(() => ({
      exitCode: 0,
      throwError: dockerEnoentError(),
    }))

    try {
      runEnvSetup(dir, { runner })
      throw new Error("expected throw")
    } catch (err) {
      expect(err).toBeInstanceOf(EnvSetupError)
      expect((err as EnvSetupError).kind).toBe("docker-not-available")
    }

    // ELF parse + dockerfile parse ran before docker, so mitigations + remote
    // are persisted even though the build never happened.
    const persisted = loadChallengeState(dir)!
    expect(persisted.mitigations).toBeDefined()
    expect(persisted.remote).toBeDefined()
    expect(persisted.docker_image).toBeUndefined()

    const journal = readFileSync(resolveJournalPath(dir), "utf-8")
    expect(journal).toContain("envsetup failed at docker-build")
  })

  test("state-missing when called before T03 loader runs", () => {
    // No T03 → no .omp/state.json
    try {
      runEnvSetup(dir, { runner: fakeImageRunner({}) })
      throw new Error("expected throw")
    } catch (err) {
      expect(err).toBeInstanceOf(EnvSetupError)
      expect((err as EnvSetupError).kind).toBe("state-missing")
    }
  })
})
