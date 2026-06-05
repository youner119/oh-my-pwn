import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { initializeOmpDir, getStatePaths } from "./io"
import {
  resolveExploitDir,
  resolveLogsDir,
  resolveArtifactsDir,
} from "./layout"

function makeChallengeDir(label: string): string {
  const dir = join(tmpdir(), `omp-io-test-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`)
  mkdirSync(dir, { recursive: true })
  return dir
}

describe("omp state io", () => {
  let challengeDir: string

  beforeEach(() => {
    challengeDir = makeChallengeDir("init")
  })

  afterEach(() => {
    if (existsSync(challengeDir)) {
      rmSync(challengeDir, { recursive: true, force: true })
    }
  })

  describe("initializeOmpDir", () => {
    test("creates .omp/, standard subdirs, and journal.md (no state.json seed)", () => {
      initializeOmpDir(challengeDir)

      const { ompDir, statePath, journalPath } = getStatePaths(challengeDir)
      expect(existsSync(ompDir)).toBe(true)
      // state.json is NOT seeded — state now lives in the db-mcp store.
      expect(existsSync(statePath)).toBe(false)
      expect(existsSync(journalPath)).toBe(true)
      expect(existsSync(resolveExploitDir(challengeDir))).toBe(true)
      expect(existsSync(resolveLogsDir(challengeDir))).toBe(true)
      expect(existsSync(resolveArtifactsDir(challengeDir))).toBe(true)
    })

    test("does not overwrite an existing journal.md", () => {
      initializeOmpDir(challengeDir)
      const { journalPath } = getStatePaths(challengeDir)
      const originalJournal = readFileSync(journalPath, "utf-8")

      initializeOmpDir(challengeDir)
      expect(readFileSync(journalPath, "utf-8")).toBe(originalJournal)
    })
  })
})
