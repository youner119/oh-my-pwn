import { describe, expect, test } from "bun:test"
import { join } from "node:path"
import {
  resolveOmpDir,
  resolveStatePath,
  resolveJournalPath,
  resolveExploitDir,
  resolveLogsDir,
  resolveArtifactsDir,
  resolveCandidatesDir,
  resolveCandidatePath,
  OMP_SUBDIRS,
} from "./layout"
import {
  EXPLOIT_DIR,
  LOGS_DIR,
  ARTIFACTS_DIR,
  CANDIDATES_DIR,
  OMP_DIR,
} from "./constants"

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

  test("resolveExploitDir / LogsDir / ArtifactsDir / CandidatesDir point at subdirs", () => {
    expect(resolveExploitDir(challengeDir)).toBe(
      join(challengeDir, OMP_DIR, EXPLOIT_DIR),
    )
    expect(resolveLogsDir(challengeDir)).toBe(
      join(challengeDir, OMP_DIR, LOGS_DIR),
    )
    expect(resolveArtifactsDir(challengeDir)).toBe(
      join(challengeDir, OMP_DIR, ARTIFACTS_DIR),
    )
    expect(resolveCandidatesDir(challengeDir)).toBe(
      join(challengeDir, OMP_DIR, CANDIDATES_DIR),
    )
  })

  test("resolveCandidatePath joins <id>.json under candidates/", () => {
    expect(resolveCandidatePath(challengeDir, "vuln_4")).toBe(
      join(challengeDir, OMP_DIR, CANDIDATES_DIR, "vuln_4.json"),
    )
  })

  test("OMP_SUBDIRS lists the four standard subdirectories", () => {
    expect([...OMP_SUBDIRS].sort()).toEqual(
      [EXPLOIT_DIR, LOGS_DIR, ARTIFACTS_DIR, CANDIDATES_DIR].sort(),
    )
  })
})
