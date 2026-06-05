/**
 * Tests for omp_setup_docker_build (post DB-cutover, T20).
 *
 * Image tag policy: image_tag_hint is REQUIRED (state.json no longer seeds
 * the binary sha, so no sha-derived fallback). Missing hint → image_tag_required.
 * + force_rebuild + EnvSetupError surfacing.
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
import { initializeOmpDir } from "../state/io"

interface Harness {
  challengeDir: string
}

async function setupHarness(): Promise<Harness> {
  const challengeDir = await mkdtemp(join(tmpdir(), "omp-setup-build-"))
  const dockerfilePath = join(challengeDir, "Dockerfile")
  await writeFile(dockerfilePath, "FROM alpine\n")
  const binaryPath = join(challengeDir, "chall")
  await writeFile(binaryPath, Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
  // Loader-shape init (.omp/ layout only — state lives in db-mcp now).
  initializeOmpDir(challengeDir)
  return { challengeDir }
}

async function teardown(h: Harness): Promise<void> {
  await rm(h.challengeDir, { recursive: true, force: true })
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
    const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))
    const t = createOmpSetupDockerBuildTool({ runner })

    const raw = await t.execute(
      { challenge_dir: h.challengeDir, image_tag_hint: "afterimage" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)

    expect(out.ok).toBe(true)
    expect(out.image_tag).toBe("afterimage")
    const buildCall = runner.calls.find((c) => c.args[0] === "build")
    expect(buildCall?.args).toContain("afterimage")
  })

  test("returns image_tag_required when hint omitted", async () => {
    const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))
    const t = createOmpSetupDockerBuildTool({ runner })

    const raw = await t.execute({ challenge_dir: h.challengeDir }, TOOL_CTX)
    const out = JSON.parse(raw as string)

    expect(out.ok).toBe(false)
    expect(out.error).toBe("image_tag_required")
    expect(out.message).toContain("image_tag_hint")
    // No build attempted without a tag.
    expect(runner.calls.some((c) => c.args[0] === "build")).toBe(false)
  })

  test("returns image_tag_required when hint is blank", async () => {
    const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))
    const t = createOmpSetupDockerBuildTool({ runner })

    const raw = await t.execute(
      { challenge_dir: h.challengeDir, image_tag_hint: "   " },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)

    expect(out.ok).toBe(false)
    expect(out.error).toBe("image_tag_required")
  })

  test("force_rebuild still runs a build", async () => {
    const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))
    const t = createOmpSetupDockerBuildTool({ runner })

    const forced = JSON.parse(
      (await t.execute(
        {
          challenge_dir: h.challengeDir,
          image_tag_hint: "afterimage",
          force_rebuild: true,
        },
        TOOL_CTX,
      )) as string,
    )
    expect(forced.ok).toBe(true)
    const buildCall = runner.calls.find((c) => c.args[0] === "build")
    expect(buildCall).toBeDefined()
    expect(buildCall?.args).toContain("--no-cache")
  })

  test("rejects non-absolute challenge_dir", async () => {
    const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))
    const t = createOmpSetupDockerBuildTool({ runner })

    const raw = await t.execute(
      { challenge_dir: "relative/path", image_tag_hint: "afterimage" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("challenge_dir_not_absolute")
  })

  test("surfaces docker-not-available as typed error", async () => {
    const runner = new FakeDockerRunner(() => ({
      exitCode: 0,
      throwError: dockerEnoentError(),
    }))
    const t = createOmpSetupDockerBuildTool({ runner })

    const raw = await t.execute(
      { challenge_dir: h.challengeDir, image_tag_hint: "afterimage" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("docker-not-available")
  })

  test("surfaces docker-build-failed as typed error with build log", async () => {
    const runner = new FakeDockerRunner(() => ({
      exitCode: 1,
      stderr: "some build error",
    }))
    const t = createOmpSetupDockerBuildTool({ runner })

    const raw = await t.execute(
      { challenge_dir: h.challengeDir, image_tag_hint: "afterimage" },
      TOOL_CTX,
    )
    const out = JSON.parse(raw as string)
    expect(out.ok).toBe(false)
    expect(out.error).toBe("docker-build-failed")
    expect(out.detail?.buildLogPath).toBeTruthy()
  })
})
