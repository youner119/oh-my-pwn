import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { loadChallengeFolder } from "./load-challenge-folder"
import { ChallengeLoadError } from "./challenge-load-error"
import { getStatePaths } from "../state/io"

function makeChallengeDir(label: string): string {
  const dir = join(
    tmpdir(),
    `omp-loader-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  )
  mkdirSync(dir, { recursive: true })
  return dir
}

describe("loadChallengeFolder (contract-load-detect-split D1)", () => {
  let dir: string

  beforeEach(() => {
    dir = makeChallengeDir("lcf")
  })

  afterEach(() => {
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  describe("happy path", () => {
    test("bootstraps .omp/ for an empty directory and marks freshlyInitialized", () => {
      const result = loadChallengeFolder(dir)

      expect(result.freshlyInitialized).toBe(true)
      expect(result.workspace_root).toBeUndefined()

      // State now lives in db-mcp; the loader only seeds the .omp/ layout +
      // journal.md and never writes state.json.
      const { ompDir, statePath, journalPath } = getStatePaths(dir)
      expect(existsSync(ompDir)).toBe(true)
      expect(existsSync(statePath)).toBe(false)
      expect(existsSync(journalPath)).toBe(true)
    })

    test("returns workspace_root when provided", () => {
      const workspace = "/host/plugin/workspace"
      const result = loadChallengeFolder(dir, { workspaceRoot: workspace })
      expect(result.workspace_root).toBe(workspace)
    })

    test("omits workspace_root when not provided", () => {
      const result = loadChallengeFolder(dir)
      expect(result.workspace_root).toBeUndefined()
    })

    test("bootstraps regardless of folder contents (no binary, no dockerfile)", () => {
      // Folder with random unrelated files — loader does not care.
      writeFileSync(join(dir, "notes.txt"), "hello\n")
      writeFileSync(join(dir, "README.md"), "challenge readme\n")

      const result = loadChallengeFolder(dir)

      expect(result.freshlyInitialized).toBe(true)
    })

    test("writes a 'challenge loaded' journal section on fresh init", () => {
      loadChallengeFolder(dir)
      const { journalPath } = getStatePaths(dir)
      const journal = readFileSync(journalPath, "utf-8")
      expect(journal).toContain("challenge loaded")
      expect(journal).toContain(`challenge_dir: \`${dir}\``)
      expect(journal).toContain("invoke omp-setup")
    })
  })

  describe("idempotency", () => {
    test("calling twice on the same directory clears freshlyInitialized", () => {
      const first = loadChallengeFolder(dir)
      const second = loadChallengeFolder(dir)

      expect(first.freshlyInitialized).toBe(true)
      // journal.md now exists → no longer fresh.
      expect(second.freshlyInitialized).toBe(false)
    })

    test("reload does not rewrite the journal 'challenge loaded' section", () => {
      loadChallengeFolder(dir)
      const { journalPath } = getStatePaths(dir)
      const journalBefore = readFileSync(journalPath, "utf-8")

      loadChallengeFolder(dir)
      const journalAfter = readFileSync(journalPath, "utf-8")

      expect(journalAfter).toBe(journalBefore)
    })
  })

  describe("error cases", () => {
    test("missing-dir when the path does not exist", () => {
      const phantom = join(tmpdir(), `omp-phantom-${Date.now()}`)
      try {
        loadChallengeFolder(phantom)
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(ChallengeLoadError)
        expect((err as ChallengeLoadError).kind).toBe("missing-dir")
      }
    })

    test("not-a-directory when the path is a file", () => {
      const filePath = join(dir, "regular.txt")
      writeFileSync(filePath, "not a dir\n")
      try {
        loadChallengeFolder(filePath)
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(ChallengeLoadError)
        expect((err as ChallengeLoadError).kind).toBe("not-a-directory")
      }
    })
  })
})
