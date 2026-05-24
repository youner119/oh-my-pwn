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
import { getStatePaths, loadChallengeState } from "../state/io"

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
      // Loader no longer touches binary / dockerfile / source — those stay
      // undefined until omp-setup Phase 0 (Detect) writes them.
      expect(result.state.binary_input_path).toBeUndefined()
      expect(result.state.binary_input_sha256).toBeUndefined()
      expect(result.state.dockerfile_path).toBeUndefined()
      expect(result.state.source_present).toBe(false)
      expect(result.state.source_paths).toEqual([])
      expect(result.state.challenge_dir).toBe(dir)

      const { ompDir, statePath, journalPath } = getStatePaths(dir)
      expect(existsSync(ompDir)).toBe(true)
      expect(existsSync(statePath)).toBe(true)
      expect(existsSync(journalPath)).toBe(true)
    })

    test("seeds workspace_root when provided", () => {
      const workspace = "/host/plugin/workspace"
      const result = loadChallengeFolder(dir, { workspaceRoot: workspace })
      expect(result.state.workspace_root).toBe(workspace)
    })

    test("omits workspace_root when not provided", () => {
      const result = loadChallengeFolder(dir)
      expect(result.state.workspace_root).toBeUndefined()
    })

    test("bootstraps regardless of folder contents (no binary, no dockerfile)", () => {
      // Folder with random unrelated files — loader does not care.
      writeFileSync(join(dir, "notes.txt"), "hello\n")
      writeFileSync(join(dir, "README.md"), "challenge readme\n")

      const result = loadChallengeFolder(dir)

      expect(result.freshlyInitialized).toBe(true)
      expect(result.state.binary_input_path).toBeUndefined()
      expect(result.state.dockerfile_path).toBeUndefined()
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
    test("calling twice on the same directory reuses state and clears freshlyInitialized", () => {
      const first = loadChallengeFolder(dir)
      const second = loadChallengeFolder(dir)

      expect(first.freshlyInitialized).toBe(true)
      expect(second.freshlyInitialized).toBe(false)
      expect(second.state.created_at).toBe(first.state.created_at)
    })

    test("reload does not rewrite the journal 'challenge loaded' section", () => {
      loadChallengeFolder(dir)
      const { journalPath } = getStatePaths(dir)
      const journalBefore = readFileSync(journalPath, "utf-8")

      loadChallengeFolder(dir)
      const journalAfter = readFileSync(journalPath, "utf-8")

      expect(journalAfter).toBe(journalBefore)
    })

    test("reload preserves agent-written state fields", () => {
      const first = loadChallengeFolder(dir)

      // Simulate omp-setup Phase 0 detect — write binary_input_path et al.
      const { statePath } = getStatePaths(dir)
      const state = loadChallengeState(dir)!
      const mutated = {
        ...state,
        binary_input_path: "/tmp/some/binary",
        binary_input_sha256: "deadbeef",
        dockerfile_path: "/tmp/some/Dockerfile",
        updated_at: state.updated_at,
      }
      writeFileSync(statePath, JSON.stringify(mutated, null, 2))

      const reloaded = loadChallengeFolder(dir)
      expect(reloaded.freshlyInitialized).toBe(false)
      expect(reloaded.state.binary_input_path).toBe("/tmp/some/binary")
      expect(reloaded.state.binary_input_sha256).toBe("deadbeef")
      expect(reloaded.state.dockerfile_path).toBe("/tmp/some/Dockerfile")
      expect(first.state.created_at).toBe(reloaded.state.created_at)
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
