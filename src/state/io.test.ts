import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  initializeOmpDir,
  loadChallengeState,
  saveChallengeState,
  ChallengeStateLoadError,
  CandidateLoadError,
  getStatePaths,
  loadCandidate,
  saveCandidate,
  deleteCandidate,
} from "./io"
import {
  resolveExploitDir,
  resolveLogsDir,
  resolveArtifactsDir,
  resolveCandidatePath,
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
    test("creates .omp/, standard subdirs, state.json, and journal.md", () => {
      const state = initializeOmpDir({
        challenge_dir: challengeDir,
        binary_input_path: `${challengeDir}/chall`,
        dockerfile_path: `${challengeDir}/Dockerfile`,
      })

      const { ompDir, statePath, journalPath } = getStatePaths(challengeDir)
      expect(existsSync(ompDir)).toBe(true)
      expect(existsSync(statePath)).toBe(true)
      expect(existsSync(journalPath)).toBe(true)
      expect(existsSync(resolveExploitDir(challengeDir))).toBe(true)
      expect(existsSync(resolveLogsDir(challengeDir))).toBe(true)
      expect(existsSync(resolveArtifactsDir(challengeDir))).toBe(true)

      // state.json content round-trips via loadChallengeState
      const reloaded = loadChallengeState(challengeDir)
      expect(reloaded).not.toBeNull()
      expect(reloaded?.challenge_dir).toBe(challengeDir)
      expect(reloaded?.binary_input_path).toBe(state.binary_input_path)
      expect(reloaded?.binary_path).toBeUndefined()
      expect(reloaded?.schema_version).toBe(state.schema_version)
    })

    test("is idempotent: second call does not overwrite state.json", () => {
      const first = initializeOmpDir({
        challenge_dir: challengeDir,
        binary_input_path: `${challengeDir}/chall`,
        dockerfile_path: `${challengeDir}/Dockerfile`,
      })
      // Mutate and persist, then re-init
      const mutated = saveChallengeState({ ...first, libc_version: "2.35" })
      const second = initializeOmpDir({
        challenge_dir: challengeDir,
        binary_input_path: `${challengeDir}/chall`,
        dockerfile_path: `${challengeDir}/Dockerfile`,
      })
      expect(second.libc_version).toBe("2.35")
      expect(second.updated_at).toBe(mutated.updated_at)
    })

    test("does not overwrite an existing journal.md", () => {
      initializeOmpDir({
        challenge_dir: challengeDir,
        binary_input_path: `${challengeDir}/chall`,
        dockerfile_path: `${challengeDir}/Dockerfile`,
      })
      const { journalPath } = getStatePaths(challengeDir)
      const originalJournal = readFileSync(journalPath, "utf-8")

      initializeOmpDir({
        challenge_dir: challengeDir,
        binary_input_path: `${challengeDir}/chall`,
        dockerfile_path: `${challengeDir}/Dockerfile`,
      })
      expect(readFileSync(journalPath, "utf-8")).toBe(originalJournal)
    })
  })

  describe("loadChallengeState", () => {
    test("returns null when state.json is absent", () => {
      expect(loadChallengeState(challengeDir)).toBeNull()
    })

    test("throws ChallengeStateLoadError on invalid JSON", () => {
      const { ompDir, statePath } = getStatePaths(challengeDir)
      mkdirSync(ompDir, { recursive: true })
      writeFileSync(statePath, "{not json", "utf-8")
      expect(() => loadChallengeState(challengeDir)).toThrow(ChallengeStateLoadError)
    })

    test("throws ChallengeStateLoadError on schema violation", () => {
      const { ompDir, statePath } = getStatePaths(challengeDir)
      mkdirSync(ompDir, { recursive: true })
      writeFileSync(statePath, JSON.stringify({ schema_version: "1" }), "utf-8")
      expect(() => loadChallengeState(challengeDir)).toThrow(ChallengeStateLoadError)
    })
  })

  describe("saveChallengeState", () => {
    test("round-trips a state through the filesystem", () => {
      const seeded = initializeOmpDir({
        challenge_dir: challengeDir,
        binary_input_path: `${challengeDir}/chall`,
        dockerfile_path: `${challengeDir}/Dockerfile`,
      })
      const saved = saveChallengeState(
        { ...seeded, libc_version: "2.31" },
        new Date("2026-04-10T01:00:00.000Z"),
      )
      expect(saved.libc_version).toBe("2.31")
      expect(saved.updated_at).toBe("2026-04-10T01:00:00.000Z")

      const reloaded = loadChallengeState(challengeDir)
      expect(reloaded?.libc_version).toBe("2.31")
      expect(reloaded?.updated_at).toBe("2026-04-10T01:00:00.000Z")
    })

    test("leaves no .tmp artifact after a successful atomic write", () => {
      const seeded = initializeOmpDir({
        challenge_dir: challengeDir,
        binary_input_path: `${challengeDir}/chall`,
        dockerfile_path: `${challengeDir}/Dockerfile`,
      })
      saveChallengeState({ ...seeded, libc_version: "2.31" })
      const { statePath } = getStatePaths(challengeDir)
      expect(existsSync(`${statePath}.tmp`)).toBe(false)
    })

    test("re-validates and throws on hand-mutated invalid state", () => {
      const seeded = initializeOmpDir({
        challenge_dir: challengeDir,
        binary_input_path: `${challengeDir}/chall`,
        dockerfile_path: `${challengeDir}/Dockerfile`,
      })
      // Simulate a caller that mutated the object past schema constraints.
      const bogus = { ...seeded, created_at: "yesterday" } as typeof seeded
      expect(() => saveChallengeState(bogus)).toThrow()
    })
  })

  describe("candidate file io (state-split P2)", () => {
    test("loadCandidate returns null when the file is missing", () => {
      expect(loadCandidate(challengeDir, "vuln_1")).toBeNull()
    })

    test("saveCandidate writes + loadCandidate round-trips", () => {
      const written = saveCandidate(challengeDir, "vuln_4", {
        id: "vuln_4",
        primitive: "heap_uaf",
        verification_result: "confirmed",
        agent: "VH-3",
        description: "release_node cleanup UAF",
        rationale: "freed node deref reachable from root daemon",
        gives: ["uaf_deref"],
        needs: ["heap_groom"],
        has_poc: true,
      })
      expect(written.id).toBe("vuln_4")
      const loaded = loadCandidate(challengeDir, "vuln_4")
      expect(loaded?.primitive).toBe("heap_uaf")
      expect(loaded?.rationale).toContain("freed node deref")
      expect(loaded?.gives).toEqual(["uaf_deref"])
    })

    test("saveCandidate cleans up tmp file (atomic)", () => {
      saveCandidate(challengeDir, "vuln_4", {
        id: "vuln_4",
        primitive: "heap_uaf",
      })
      const path = resolveCandidatePath(challengeDir, "vuln_4")
      expect(existsSync(`${path}.tmp`)).toBe(false)
    })

    test("saveCandidate rejects id mismatch between arg and candidate.id", () => {
      expect(() =>
        saveCandidate(challengeDir, "vuln_4", {
          id: "vuln_5",
          primitive: "stack_bof",
        }),
      ).toThrow(/id mismatch/)
    })

    test("loadCandidate / saveCandidate / deleteCandidate reject invalid ids", () => {
      expect(() => loadCandidate(challengeDir, "vuln/4")).toThrow(/Invalid candidate id/)
      expect(() =>
        saveCandidate(challengeDir, "vuln 4", { id: "vuln 4", primitive: "x" }),
      ).toThrow(/Invalid candidate id/)
      expect(() => deleteCandidate(challengeDir, "../escape")).toThrow(
        /Invalid candidate id/,
      )
    })

    test("loadCandidate throws CandidateLoadError on malformed JSON", () => {
      const path = resolveCandidatePath(challengeDir, "vuln_4")
      mkdirSync(join(challengeDir, ".omp", "candidates"), { recursive: true })
      writeFileSync(path, "{not json", "utf-8")
      expect(() => loadCandidate(challengeDir, "vuln_4")).toThrow(CandidateLoadError)
    })

    test("loadCandidate throws CandidateLoadError on schema violation", () => {
      const path = resolveCandidatePath(challengeDir, "vuln_4")
      mkdirSync(join(challengeDir, ".omp", "candidates"), { recursive: true })
      // Missing required `primitive`.
      writeFileSync(path, JSON.stringify({ id: "vuln_4" }), "utf-8")
      expect(() => loadCandidate(challengeDir, "vuln_4")).toThrow(CandidateLoadError)
    })

    test("deleteCandidate returns true when present, false when missing", () => {
      saveCandidate(challengeDir, "vuln_4", { id: "vuln_4", primitive: "x" })
      expect(deleteCandidate(challengeDir, "vuln_4")).toBe(true)
      expect(deleteCandidate(challengeDir, "vuln_4")).toBe(false)
    })
  })
})
