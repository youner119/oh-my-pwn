import { describe, expect, test } from "bun:test"
import { join } from "node:path"
import {
  resolveOmpDir,
  resolveStatePath,
  resolveJournalPath,
  resolveExploitDir,
  resolveLogsDir,
  resolveArtifactsDir,
  OMP_SUBDIRS,
} from "./layout"
import { EXPLOIT_DIR, LOGS_DIR, ARTIFACTS_DIR, OMP_DIR } from "./constants"

describe("omp state layout", () => {
  const challengeDir = "/tmp/fake-challenge"

  test("resolveOmpDir joins .omp under the challenge dir", () => {
    expect(resolveOmpDir(challengeDir)).toBe(join(challengeDir, OMP_DIR))
  })

  test("resolveStatePath points at .omp/state.json", () => {
    expect(resolveStatePath(challengeDir)).toBe(
      join(challengeDir, OMP_DIR, "state.json"),
    )
  })

  test("resolveJournalPath points at .omp/journal.md", () => {
    expect(resolveJournalPath(challengeDir)).toBe(
      join(challengeDir, OMP_DIR, "journal.md"),
    )
  })

  test("resolveExploitDir / LogsDir / ArtifactsDir point at subdirs", () => {
    expect(resolveExploitDir(challengeDir)).toBe(
      join(challengeDir, OMP_DIR, EXPLOIT_DIR),
    )
    expect(resolveLogsDir(challengeDir)).toBe(
      join(challengeDir, OMP_DIR, LOGS_DIR),
    )
    expect(resolveArtifactsDir(challengeDir)).toBe(
      join(challengeDir, OMP_DIR, ARTIFACTS_DIR),
    )
  })

  test("OMP_SUBDIRS lists the three standard subdirectories", () => {
    expect([...OMP_SUBDIRS].sort()).toEqual(
      [EXPLOIT_DIR, LOGS_DIR, ARTIFACTS_DIR].sort(),
    )
  })
})
