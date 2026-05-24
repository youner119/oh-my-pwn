/**
 * Tests for omp_setup_docker_build (T04).
 *
 * Image tag policy verification (D4 — α):
 *   - image_tag_hint wins when provided
 *   - falls back to omp-<sha8 from binary_input_sha256> when not
 *   - falls back to binary_sha256 if binary_input_sha256 missing (legacy)
 *   - refuses if neither hint nor sha available
 * + force_rebuild bypass + EnvSetupError surfacing.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createOmpSetupDockerBuildTool } from "./omp-setup-docker-build"
import {
  FakeDockerRunner,
  dockerEnoentError,
} from "../envsetup/fake-docker-runner"
import { initializeOmpDir, saveChallengeState } from "../state/io"
import type { ChallengeState } from "../state/challenge-state"

interface Harness {
  challengeDir: string
}

async function setupHarness(): Promise<Harness> {
  const challengeDir = await mkdtemp(join(tmpdir(), "omp-setup-build-"))
  const dockerfilePath = join(challengeDir, "Dockerfile")
  await writeFile(dockerfilePath, "FROM alpine\n")
  const binaryPath = join(challengeDir, "chall")
  await writeFile(binaryPath, Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
  // Loader-shape init (challenge_dir only) + setup-Phase-0 detect stamp via
  // saveChallengeState — matches the contract-load-detect-split flow.
  const initial = initializeOmpDir({ challenge_dir: challengeDir })
  saveChallengeState({
    ...initial,
    binary_input_path: binaryPath,
    dockerfile_path: dockerfilePath,
  })
  return { challengeDir }
}

async function teardown(h: Harness): Promise<void> {
  await rm(h.challengeDir, { recursive: true, force: true })
}

function seedSha(
  h: Harness,
  fields: Partial<ChallengeState>,
): ChallengeState {
  const initial = initializeOmpDir({ challenge_dir: h.challengeDir })
  return saveChallengeState({
    ...initial,
    binary_input_path: join(h.challengeDir, "chall"),
    dockerfile_path: join(h.challengeDir, "Dockerfile"),
    ...fields,
  })
}

const TOOL_CTX = {
  sessionID: "s",
  messageID: "m",
  abort: new AbortController().signal,
  metadata: () => {},
} as never

describe("omp_setup_docker_build", () => {
  let h: Harness

  beforeEach(async () => {
    h = await setupHarness()
  })
  afterEach(async () => {
    await teardown(h)
  })

  test("uses image_tag_hint as the tag", async () => {
    seedSha(h, {
      binary_input_sha256:
        "b3ae5f5113462273249bfb295cd2eb5027f98a5ad50a33876935b435b2a9a9ca",
    })
    const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))
    const t = createOmpSetupDockerBuildTool({ runner })

    const raw = await t.execute(
      { challenge_dir: h.challengeDir, image_tag_hint: "afterimage" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)

    expect(out.ok).toBe(true)
    expect(out.image_tag).toBe("afterimage")
    expect(out.cached).toBe(false)
    const buildCall = runner.calls.find((c) => c.args[0] === "build")
    expect(buildCall?.args).toContain("afterimage")
    // sha-derived default must NOT have been used.
    expect(buildCall?.args).not.toContain("omp-b3ae5f51")
  })

  test("falls back to omp-<sha8> from binary_input_sha256 when hint omitted", async () => {
    seedSha(h, {
      binary_input_sha256:
        "b3ae5f5113462273249bfb295cd2eb5027f98a5ad50a33876935b435b2a9a9ca",
    })
    const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))
    const t = createOmpSetupDockerBuildTool({ runner })

    const raw = await t.execute({ challenge_dir: h.challengeDir }, TOOL_CTX)
    const out = JSON.parse(raw as string)

    expect(out.ok).toBe(true)
    expect(out.image_tag).toBe("omp-b3ae5f51")
  })

  test("falls back to binary_sha256 when binary_input_sha256 missing (legacy state)", async () => {
    seedSha(h, {
      binary_sha256:
        "deadbeefcafebabe1234567890abcdef1234567890abcdef1234567890abcdef",
      // binary_input_sha256 intentionally absent
    })
    const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))
    const t = createOmpSetupDockerBuildTool({ runner })

    const raw = await t.execute({ challenge_dir: h.challengeDir }, TOOL_CTX)
    const out = JSON.parse(raw as string)

    expect(out.ok).toBe(true)
    expect(out.image_tag).toBe("omp-deadbeef")
  })

  test("hint wins even when binary_sha256 is absent (Phase 1 entry case)", async () => {
    // Phase 1 scenario: setup agent has patched state with binary_input_path
    // but no sha yet (or input sha only). image_tag_hint must work.
    seedSha(h, {
      // no sha fields at all
    })
    const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))
    const t = createOmpSetupDockerBuildTool({ runner })

    const raw = await t.execute(
      { challenge_dir: h.challengeDir, image_tag_hint: "kaleido" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)

    expect(out.ok).toBe(true)
    expect(out.image_tag).toBe("kaleido")
  })

  test("returns no_input_sha when neither hint nor sha available", async () => {
    seedSha(h, {})  // no sha set
    const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))
    const t = createOmpSetupDockerBuildTool({ runner })

    const raw = await t.execute({ challenge_dir: h.challengeDir }, TOOL_CTX)
    const out = JSON.parse(raw as string)

    expect(out.ok).toBe(false)
    expect(out.error).toBe("no_input_sha")
    expect(out.message).toContain("image_tag_hint")
  })

  test("force_rebuild bypasses cache reuse", async () => {
    seedSha(h, {
      binary_input_sha256:
        "b3ae5f5113462273249bfb295cd2eb5027f98a5ad50a33876935b435b2a9a9ca",
      docker_image: "omp-b3ae5f51",  // pretend cache hit
    })
    const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))
    const t = createOmpSetupDockerBuildTool({ runner })

    // Without force_rebuild: cache hit (no build invocation).
    const cached = JSON.parse(
      (await t.execute({ challenge_dir: h.challengeDir }, TOOL_CTX)) as string,
    )
    expect(cached.cached).toBe(true)
    expect(runner.calls.some((c) => c.args[0] === "build")).toBe(false)

    // With force_rebuild: build runs even with cache.
    const forced = JSON.parse(
      (await t.execute(
        { challenge_dir: h.challengeDir, force_rebuild: true },
        TOOL_CTX,
      )) as string,
    )
    expect(forced.cached).toBe(false)
    expect(runner.calls.some((c) => c.args[0] === "build")).toBe(true)
  })

  test("rejects non-absolute challenge_dir", async () => {
    const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))
    const t = createOmpSetupDockerBuildTool({ runner })

    const raw = await t.execute(
      { challenge_dir: "relative/path" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("challenge_dir_not_absolute")
  })

  test("returns state_missing when .omp/state.json does not exist", async () => {
    const empty = await mkdtemp(join(tmpdir(), "omp-no-state-"))
    const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))
    const t = createOmpSetupDockerBuildTool({ runner })

    const raw = await t.execute({ challenge_dir: empty }, TOOL_CTX)
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("state_missing")

    await rm(empty, { recursive: true, force: true })
  })

  test("surfaces docker-not-available as typed error", async () => {
    seedSha(h, {
      binary_input_sha256:
        "b3ae5f5113462273249bfb295cd2eb5027f98a5ad50a33876935b435b2a9a9ca",
    })
    const runner = new FakeDockerRunner(() => ({
      exitCode: 0,
      throwError: dockerEnoentError(),
    }))
    const t = createOmpSetupDockerBuildTool({ runner })

    const raw = await t.execute({ challenge_dir: h.challengeDir }, TOOL_CTX)
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("docker-not-available")
  })

  test("surfaces docker-build-failed as typed error with build log", async () => {
    seedSha(h, {
      binary_input_sha256:
        "b3ae5f5113462273249bfb295cd2eb5027f98a5ad50a33876935b435b2a9a9ca",
    })
    const runner = new FakeDockerRunner(() => ({
      exitCode: 1,
      stderr: "some build error",
    }))
    const t = createOmpSetupDockerBuildTool({ runner })

    const raw = await t.execute({ challenge_dir: h.challengeDir }, TOOL_CTX)
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("docker-build-failed")
    expect(out.detail?.buildLogPath).toBeTruthy()
  })
})
