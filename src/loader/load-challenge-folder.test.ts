import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { createHash } from "node:crypto"
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
import { loadChallengeFolder } from "./load-challenge-folder"
import { ChallengeLoadError } from "./challenge-load-error"
import {
  ChallengeStateLoadError,
  getStatePaths,
  loadChallengeState,
  saveChallengeState,
} from "../state/io"

const ELF_HEADER = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00])

function makeChallengeDir(label: string): string {
  const dir = join(
    tmpdir(),
    `omp-loader-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  )
  mkdirSync(dir, { recursive: true })
  return dir
}

function writeBinary(
  dir: string,
  name: string,
  bytes: Buffer = ELF_HEADER,
  mode = 0o755,
): string {
  const path = join(dir, name)
  writeFileSync(path, bytes)
  chmodSync(path, mode)
  return path
}

function writeText(dir: string, name: string, content: string, mode = 0o644): string {
  const path = join(dir, name)
  writeFileSync(path, content)
  chmodSync(path, mode)
  return path
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex")
}

function seedMinimalChallenge(dir: string, options: { sourceFile?: string } = {}): {
  binaryPath: string
  dockerfilePath: string
} {
  const binaryPath = writeBinary(dir, "chall")
  const dockerfilePath = writeText(dir, "Dockerfile", "FROM ubuntu:22.04\nCMD [\"/chall\"]\n")
  if (options.sourceFile !== undefined) {
    writeText(dir, options.sourceFile, "int main(void){return 0;}\n")
  }
  return { binaryPath, dockerfilePath }
}

describe("loadChallengeFolder", () => {
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
    test("bootstraps .omp/, persists input identity, marks freshlyInitialized", () => {
      const { binaryPath, dockerfilePath } = seedMinimalChallenge(dir)
      const expectedSha = sha256(ELF_HEADER)

      const result = loadChallengeFolder(dir)

      expect(result.freshlyInitialized).toBe(true)
      expect(result.shaDrift).toBe(false)
      // Loader seeds INPUT identity only. The patched-copy fields
      // (binary_path / binary_sha256) belong to the omp-setup agent.
      expect(result.state.binary_input_path).toBe(binaryPath)
      expect(result.state.binary_input_sha256).toBe(expectedSha)
      expect(result.state.binary_path).toBeUndefined()
      expect(result.state.binary_sha256).toBeUndefined()
      expect(result.state.dockerfile_path).toBe(dockerfilePath)
      expect(result.state.source_present).toBe(false)
      expect(result.state.source_paths).toEqual([])

      const { ompDir, statePath, journalPath } = getStatePaths(dir)
      expect(existsSync(ompDir)).toBe(true)
      expect(existsSync(statePath)).toBe(true)
      expect(existsSync(journalPath)).toBe(true)

      const persisted = loadChallengeState(dir)
      expect(persisted?.binary_input_sha256).toBe(expectedSha)
      expect(persisted?.binary_path).toBeUndefined()

      const journal = readFileSync(journalPath, "utf-8")
      expect(journal).toContain("## challenge loaded")
      expect(journal).toContain(expectedSha)
    })

    test("seeds workspace_root from opts (T01.6)", () => {
      seedMinimalChallenge(dir)
      const result = loadChallengeFolder(dir, {
        workspaceRoot: "/abs/plugin-root/workspace",
      })
      expect(result.state.workspace_root).toBe("/abs/plugin-root/workspace")
    })

    test("workspace_root stays undefined when opts.workspaceRoot omitted", () => {
      seedMinimalChallenge(dir)
      const result = loadChallengeFolder(dir)
      expect(result.state.workspace_root).toBeUndefined()
    })

    test("seeds binary_input_path from the loader-resolved file", () => {
      const { binaryPath } = seedMinimalChallenge(dir)
      const result = loadChallengeFolder(dir)
      expect(result.state.binary_input_path).toBe(binaryPath)
      // binary_path is reserved for the omp-setup agent's Phase 3 patched
      // copy. The loader must not pre-seed it.
      expect(result.state.binary_path).toBeUndefined()
    })

    test("seeds binary_input_sha256 from the loader-resolved file", () => {
      seedMinimalChallenge(dir)
      const expectedSha = sha256(ELF_HEADER)
      const result = loadChallengeFolder(dir)
      expect(result.state.binary_input_sha256).toBe(expectedSha)
      // binary_sha256 stays undefined until omp-setup writes the patched
      // copy's hash.
      expect(result.state.binary_sha256).toBeUndefined()
    })

    test("backfills binary_input_{path,sha256} on reload of a pre-T01.6 state", () => {
      // Simulate a state.json written before the input-identity fields
      // existed (an earlier OmP version): binary_input_* are missing but
      // legacy `binary_path` / `binary_sha256` may be present. The loader
      // is the only writer that can repair this — `omp_patch_state` would
      // strip those fields as protected.
      const { binaryPath } = seedMinimalChallenge(dir)
      const expectedSha = sha256(ELF_HEADER)
      loadChallengeFolder(dir)
      // Strip the input-identity fields to mimic a stale state.json. Also
      // re-introduce a legacy `binary_path` / `binary_sha256` pair the way
      // pre-omp-setup OmP versions wrote them.
      const { statePath } = getStatePaths(dir)
      const raw = JSON.parse(readFileSync(statePath, "utf-8"))
      delete raw.binary_input_path
      delete raw.binary_input_sha256
      raw.binary_path = binaryPath
      raw.binary_sha256 = expectedSha
      writeFileSync(statePath, JSON.stringify(raw))

      const reloaded = loadChallengeFolder(dir)
      expect(reloaded.state.binary_input_path).toBe(binaryPath)
      expect(reloaded.state.binary_input_sha256).toBe(expectedSha)
      // Legacy binary_path / binary_sha256 are preserved untouched; the
      // omp-setup agent overwrites them on the next setup run.
      expect(reloaded.state.binary_path).toBe(binaryPath)
      expect(reloaded.state.binary_sha256).toBe(expectedSha)
      expect(reloaded.shaDrift).toBe(false)
    })

    test("backfill on reload does NOT append a 'challenge loaded' journal section", () => {
      // Fresh init records "challenge loaded"; backfill should be silent so
      // upgrading OmP versions does not retroactively spam the journal.
      seedMinimalChallenge(dir)
      const { statePath, journalPath } = getStatePaths(dir)
      loadChallengeFolder(dir)

      const raw = JSON.parse(readFileSync(statePath, "utf-8"))
      delete raw.binary_input_path
      delete raw.binary_input_sha256
      writeFileSync(statePath, JSON.stringify(raw))

      const journalBefore = readFileSync(journalPath, "utf-8")
      const occurrencesBefore =
        journalBefore.split("## challenge loaded").length - 1

      loadChallengeFolder(dir)

      const journalAfter = readFileSync(journalPath, "utf-8")
      const occurrencesAfter =
        journalAfter.split("## challenge loaded").length - 1
      expect(occurrencesAfter).toBe(occurrencesBefore)
    })

    test("records C source when present and sets source_present=true", () => {
      seedMinimalChallenge(dir, { sourceFile: "chall.c" })

      const result = loadChallengeFolder(dir)

      expect(result.state.source_present).toBe(true)
      expect(result.state.source_paths).toEqual([join(dir, "chall.c")])
    })

    test("auto-detects binary even when libc.so.6 is shipped alongside", () => {
      const { binaryPath } = seedMinimalChallenge(dir)
      writeBinary(dir, "libc.so.6")
      writeBinary(dir, "ld-linux-x86-64.so.2")

      const result = loadChallengeFolder(dir)

      expect(result.state.binary_input_path).toBe(binaryPath)
    })

    test("accepts an explicit binary basename via opts.binary", () => {
      const { binaryPath } = seedMinimalChallenge(dir)
      // Add a second valid candidate so auto-detect would fail.
      writeBinary(dir, "decoy")

      const result = loadChallengeFolder(dir, { binary: "chall" })

      expect(result.state.binary_input_path).toBe(binaryPath)
    })

    test("accepts an explicit binary as an absolute path", () => {
      const { binaryPath } = seedMinimalChallenge(dir)
      writeBinary(dir, "decoy")

      const result = loadChallengeFolder(dir, { binary: binaryPath })

      expect(result.state.binary_input_path).toBe(binaryPath)
    })

    test("accepts dockerfile in lowercase form", () => {
      writeBinary(dir, "chall")
      writeText(dir, "dockerfile", "FROM ubuntu:22.04\n")

      const result = loadChallengeFolder(dir)

      expect(result.state.dockerfile_path).toBe(join(dir, "dockerfile"))
    })
  })

  describe("nested-layout hints (real CTF folders)", () => {
    test("binary + Dockerfile both inside deploy/ via explicit hints", () => {
      // Realistic layout:
      //   chall/
      //     deploy/{Dockerfile, chall}
      //     src/chall.c
      //     README.md
      mkdirSync(join(dir, "deploy"), { recursive: true })
      const binaryPath = writeBinary(join(dir, "deploy"), "chall")
      const dockerfilePath = writeText(
        join(dir, "deploy"),
        "Dockerfile",
        "FROM ubuntu:22.04\nCMD [\"/chall\"]\n",
      )
      writeText(dir, "README.md", "# challenge\n")

      const result = loadChallengeFolder(dir, {
        binary: "deploy/chall",
        dockerfile: "deploy/Dockerfile",
      })

      expect(result.state.binary_input_path).toBe(binaryPath)
      expect(result.state.dockerfile_path).toBe(dockerfilePath)
      expect(result.freshlyInitialized).toBe(true)
    })

    test("dockerfile hint accepts an absolute path", () => {
      mkdirSync(join(dir, "deploy"), { recursive: true })
      writeBinary(join(dir, "deploy"), "chall")
      const dockerfilePath = writeText(
        join(dir, "deploy"),
        "Dockerfile",
        "FROM ubuntu\n",
      )

      const result = loadChallengeFolder(dir, {
        binary: "deploy/chall",
        dockerfile: dockerfilePath, // absolute
      })

      expect(result.state.dockerfile_path).toBe(dockerfilePath)
    })

    test("dockerfile hint accepts a non-standard filename like Dockerfile.prod", () => {
      mkdirSync(join(dir, "deploy"), { recursive: true })
      writeBinary(join(dir, "deploy"), "chall")
      writeText(join(dir, "deploy"), "Dockerfile.prod", "FROM ubuntu\n")
      writeText(join(dir, "deploy"), "Dockerfile.dev", "FROM ubuntu:dev\n")

      const result = loadChallengeFolder(dir, {
        binary: "deploy/chall",
        dockerfile: "deploy/Dockerfile.prod",
      })

      expect(result.state.dockerfile_path).toBe(
        join(dir, "deploy", "Dockerfile.prod"),
      )
    })

    test("missing-dockerfile when explicit hint points at a nonexistent path", () => {
      writeBinary(dir, "chall")
      writeText(dir, "Dockerfile", "FROM alpine\n")
      try {
        loadChallengeFolder(dir, { dockerfile: "deploy/Dockerfile" })
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(ChallengeLoadError)
        expect((err as ChallengeLoadError).kind).toBe("missing-dockerfile")
      }
    })

    test("missing-dockerfile when explicit hint points at a directory", () => {
      writeBinary(dir, "chall")
      mkdirSync(join(dir, "deploy"), { recursive: true })
      try {
        loadChallengeFolder(dir, { dockerfile: "deploy" })
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(ChallengeLoadError)
        expect((err as ChallengeLoadError).kind).toBe("missing-dockerfile")
      }
    })

    test("auto-detect of Dockerfile still works when only binary hint is given", () => {
      // binary in deploy/, Dockerfile at the root — only binary needs a hint
      mkdirSync(join(dir, "deploy"), { recursive: true })
      writeBinary(join(dir, "deploy"), "chall")
      const dockerfilePath = writeText(dir, "Dockerfile", "FROM ubuntu\n")

      const result = loadChallengeFolder(dir, { binary: "deploy/chall" })

      expect(result.state.dockerfile_path).toBe(dockerfilePath)
    })
  })

  describe("idempotent reload (load-or-init)", () => {
    test("returns persisted state on second call without journal noise", () => {
      seedMinimalChallenge(dir)
      const first = loadChallengeFolder(
        dir,
        {},
        new Date("2026-04-11T00:00:00.000Z"),
      )

      const { journalPath } = getStatePaths(dir)
      const journalAfterFirst = readFileSync(journalPath, "utf-8")

      const second = loadChallengeFolder(
        dir,
        {},
        new Date("2026-04-11T01:00:00.000Z"),
      )

      expect(second.freshlyInitialized).toBe(false)
      expect(second.shaDrift).toBe(false)
      // updated_at must come from the persisted state, not from the second call's `now`.
      expect(second.state.updated_at).toBe(first.state.updated_at)
      expect(second.state.binary_input_sha256).toBe(first.state.binary_input_sha256)

      const journalAfterSecond = readFileSync(journalPath, "utf-8")
      expect(journalAfterSecond).toBe(journalAfterFirst)
    })

    test("preserves user-mutated fields across reload", () => {
      seedMinimalChallenge(dir)
      const first = loadChallengeFolder(dir)
      saveChallengeState({ ...first.state, libc_version: "2.35" })

      const second = loadChallengeFolder(dir)

      expect(second.state.libc_version).toBe("2.35")
    })
  })

  describe("binary sha drift", () => {
    test("flags drift on input identity change, journals it, and does NOT mutate state.json", () => {
      seedMinimalChallenge(dir)
      const first = loadChallengeFolder(dir)
      // Drift is detected against the INPUT identity sha (the loader
      // captures this; the patched-copy `binary_sha256` is owned by
      // omp-setup and would false-positive on every post-setup reload).
      const originalSha = first.state.binary_input_sha256
      expect(originalSha).toBeDefined()

      // Replace the binary with different bytes (still valid ELF magic).
      const newBytes = Buffer.concat([ELF_HEADER, Buffer.from("DRIFT")])
      writeBinary(dir, "chall", newBytes)
      const newSha = sha256(newBytes)
      expect(newSha).not.toBe(originalSha)

      const second = loadChallengeFolder(dir)

      expect(second.shaDrift).toBe(true)
      // state.binary_input_sha256 must still match the persisted (original)
      // identity — the loader records drift in the journal but never mutates
      // state.json.
      expect(second.state.binary_input_sha256).toBe(originalSha)

      const persisted = loadChallengeState(dir)
      expect(persisted?.binary_input_sha256).toBe(originalSha)

      const { journalPath } = getStatePaths(dir)
      const journal = readFileSync(journalPath, "utf-8")
      expect(journal).toContain("## binary sha drift")
      expect(journal).toContain(originalSha!)
      expect(journal).toContain(newSha)
    })

    test("does NOT flag drift when only the patched copy hash differs", () => {
      // Simulate a successfully-set-up challenge: omp-setup wrote
      // `binary_path` + `binary_sha256` (patched copy hash) while
      // `binary_input_*` describe the untouched input. The next loader call
      // must compare against `binary_input_sha256`, not `binary_sha256`,
      // otherwise every post-setup reload looks like drift.
      seedMinimalChallenge(dir)
      const first = loadChallengeFolder(dir)
      // Forge a "post-setup" state by setting a different binary_sha256
      // while leaving the input identity intact.
      saveChallengeState({
        ...first.state,
        binary_path: `${first.state.challenge_dir}/.omp/artifacts/chall`,
        binary_sha256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      })

      const reload = loadChallengeFolder(dir)
      expect(reload.shaDrift).toBe(false)
    })
  })

  describe("error cases", () => {
    test("missing-dir when the directory does not exist", () => {
      const ghost = join(dir, "nope")
      try {
        loadChallengeFolder(ghost)
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(ChallengeLoadError)
        expect((err as ChallengeLoadError).kind).toBe("missing-dir")
      }
    })

    test("not-a-directory when the path is a file", () => {
      const filePath = writeText(dir, "actually-a-file", "hi\n")
      try {
        loadChallengeFolder(filePath)
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(ChallengeLoadError)
        expect((err as ChallengeLoadError).kind).toBe("not-a-directory")
      }
    })

    test("missing-dockerfile when no Dockerfile is present", () => {
      writeBinary(dir, "chall")
      try {
        loadChallengeFolder(dir)
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(ChallengeLoadError)
        expect((err as ChallengeLoadError).kind).toBe("missing-dockerfile")
      }
    })

    test("ambiguous-binary (none) when only a Dockerfile and notes are present", () => {
      writeText(dir, "Dockerfile", "FROM ubuntu\n")
      writeText(dir, "README.md", "## challenge\n")
      try {
        loadChallengeFolder(dir)
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(ChallengeLoadError)
        const e = err as ChallengeLoadError
        expect(e.kind).toBe("ambiguous-binary")
        if (e.detail.kind === "ambiguous-binary") {
          expect(e.detail.reason).toBe("none")
        }
      }
    })

    test("ambiguous-binary (multiple) when two candidates exist", () => {
      writeBinary(dir, "chall_a")
      writeBinary(dir, "chall_b")
      writeText(dir, "Dockerfile", "FROM ubuntu\n")
      try {
        loadChallengeFolder(dir)
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(ChallengeLoadError)
        const e = err as ChallengeLoadError
        expect(e.kind).toBe("ambiguous-binary")
        if (e.detail.kind === "ambiguous-binary") {
          expect(e.detail.reason).toBe("multiple")
          expect(e.detail.candidates.length).toBe(2)
        }
      }
    })

    test("missing-binary when an explicit hint points at a nonexistent file", () => {
      seedMinimalChallenge(dir)
      try {
        loadChallengeFolder(dir, { binary: "ghost" })
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(ChallengeLoadError)
        expect((err as ChallengeLoadError).kind).toBe("missing-binary")
      }
    })

    test("binary-not-elf when an explicit hint targets a plain file", () => {
      writeText(dir, "Dockerfile", "FROM ubuntu\n")
      writeText(dir, "run.sh", "#!/bin/sh\n", 0o755)
      try {
        loadChallengeFolder(dir, { binary: "run.sh" })
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(ChallengeLoadError)
        expect((err as ChallengeLoadError).kind).toBe("binary-not-elf")
      }
    })

    test("propagates ChallengeStateLoadError when state.json is corrupt on reload", () => {
      seedMinimalChallenge(dir)
      loadChallengeFolder(dir)

      // Corrupt the persisted state by overwriting it with invalid JSON.
      const { statePath } = getStatePaths(dir)
      writeFileSync(statePath, "{not json", "utf-8")

      try {
        loadChallengeFolder(dir)
        throw new Error("expected throw")
      } catch (err) {
        // Loader does NOT translate this into a ChallengeLoadError — the
        // underlying ChallengeStateLoadError is more informative and the
        // call site should distinguish state corruption from input-contract
        // failures.
        expect(err).toBeInstanceOf(ChallengeStateLoadError)
      }
    })

    test("binary-not-executable when an explicit hint targets an ELF without exec bit", () => {
      writeText(dir, "Dockerfile", "FROM ubuntu\n")
      writeBinary(dir, "chall", ELF_HEADER, 0o644)
      try {
        loadChallengeFolder(dir, { binary: "chall" })
        throw new Error("expected throw")
      } catch (err) {
        expect(err).toBeInstanceOf(ChallengeLoadError)
        expect((err as ChallengeLoadError).kind).toBe("binary-not-executable")
      }
    })
  })
})
