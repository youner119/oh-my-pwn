import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  appendJournalSection,
  appendUserCorrection,
  initializeJournal,
} from "./journal"
import { initializeOmpDir } from "./io"
import { resolveJournalPath } from "./layout"
import { createInitialChallengeState } from "./challenge-state"

function makeChallengeDir(label: string): string {
  const dir = join(
    tmpdir(),
    `omp-journal-test-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  )
  mkdirSync(dir, { recursive: true })
  return dir
}

describe("omp journal", () => {
  let challengeDir: string

  beforeEach(() => {
    challengeDir = makeChallengeDir("append")
  })

  afterEach(() => {
    if (existsSync(challengeDir)) {
      rmSync(challengeDir, { recursive: true, force: true })
    }
  })

  test("initializeJournal writes a read-only notice header on first call", () => {
    initializeOmpDir({
      challenge_dir: challengeDir,
      binary_input_path: `${challengeDir}/chall`,
      dockerfile_path: `${challengeDir}/Dockerfile`,
    })
    const contents = readFileSync(resolveJournalPath(challengeDir), "utf-8")
    expect(contents).toContain("# oh-my-pwn Handoff Journal")
    expect(contents).toContain("append-only progress log")
    expect(contents).toContain("read-only for humans")
  })

  test("initializeJournal is a no-op when the journal already exists", () => {
    initializeOmpDir({
      challenge_dir: challengeDir,
      binary_input_path: `${challengeDir}/chall`,
      dockerfile_path: `${challengeDir}/Dockerfile`,
    })
    const before = readFileSync(resolveJournalPath(challengeDir), "utf-8")

    // Directly call initializeJournal a second time with a fake state
    const fakeState = createInitialChallengeState({
      challenge_dir: challengeDir,
      binary_input_path: `${challengeDir}/chall`,
      dockerfile_path: `${challengeDir}/Dockerfile`,
    })
    initializeJournal(challengeDir, fakeState, new Date("2030-01-01T00:00:00Z"))

    const after = readFileSync(resolveJournalPath(challengeDir), "utf-8")
    expect(after).toBe(before)
  })

  test("appendJournalSection appends a timestamped heading", () => {
    initializeOmpDir({
      challenge_dir: challengeDir,
      binary_input_path: `${challengeDir}/chall`,
      dockerfile_path: `${challengeDir}/Dockerfile`,
    })
    appendJournalSection(
      challengeDir,
      "EnvSetup",
      "detected glibc 2.31",
      new Date("2026-04-10T05:00:00.000Z"),
    )
    const contents = readFileSync(resolveJournalPath(challengeDir), "utf-8")
    expect(contents).toContain("## EnvSetup — 2026-04-10T05:00:00.000Z")
    expect(contents).toContain("detected glibc 2.31")
  })

  test("multiple appends preserve order and never rewrite earlier sections", () => {
    initializeOmpDir({
      challenge_dir: challengeDir,
      binary_input_path: `${challengeDir}/chall`,
      dockerfile_path: `${challengeDir}/Dockerfile`,
    })
    appendJournalSection(challengeDir, "First", "a", new Date("2026-04-10T05:00:00Z"))
    appendJournalSection(challengeDir, "Second", "b", new Date("2026-04-10T05:01:00Z"))
    appendJournalSection(challengeDir, "Third", "c", new Date("2026-04-10T05:02:00Z"))

    const contents = readFileSync(resolveJournalPath(challengeDir), "utf-8")
    const firstIdx = contents.indexOf("## First")
    const secondIdx = contents.indexOf("## Second")
    const thirdIdx = contents.indexOf("## Third")
    expect(firstIdx).toBeGreaterThan(0)
    expect(secondIdx).toBeGreaterThan(firstIdx)
    expect(thirdIdx).toBeGreaterThan(secondIdx)
  })

  test("appendUserCorrection preserves user_text verbatim in a quote block", () => {
    initializeOmpDir({
      challenge_dir: challengeDir,
      binary_input_path: `${challengeDir}/chall`,
      dockerfile_path: `${challengeDir}/Dockerfile`,
    })
    appendUserCorrection(challengeDir, {
      timestamp: "2026-04-10T06:00:00.000Z",
      user_text: "libc는 2.35야\n한 줄 더",
      applied_delta: "libc_version 2.31 → 2.35",
    })
    const contents = readFileSync(resolveJournalPath(challengeDir), "utf-8")
    expect(contents).toContain("## User correction — 2026-04-10T06:00:00.000Z")
    expect(contents).toContain("**Applied delta:** libc_version 2.31 → 2.35")
    expect(contents).toContain("> libc는 2.35야")
    expect(contents).toContain("> 한 줄 더")
  })

  test("appendUserCorrection preserves microsecond precision without Date round-trip", () => {
    initializeOmpDir({
      challenge_dir: challengeDir,
      binary_input_path: `${challengeDir}/chall`,
      dockerfile_path: `${challengeDir}/Dockerfile`,
    })
    const microsecondStamp = "2026-04-10T06:00:00.123456Z"
    appendUserCorrection(challengeDir, {
      timestamp: microsecondStamp,
      user_text: "precision test",
    })
    const contents = readFileSync(resolveJournalPath(challengeDir), "utf-8")
    expect(contents).toContain(`## User correction — ${microsecondStamp}`)
  })

  test("appendJournalSection creates .omp/ on demand when called before initializeOmpDir", () => {
    // No prior initializeOmpDir — this simulates a T19 hook that fired
    // before the expected bootstrap order.
    appendJournalSection(
      challengeDir,
      "Hook fired early",
      "out-of-order smoke",
      new Date("2026-04-10T07:00:00.000Z"),
    )
    const contents = readFileSync(resolveJournalPath(challengeDir), "utf-8")
    expect(contents).toContain("## Hook fired early — 2026-04-10T07:00:00.000Z")
    expect(contents).toContain("out-of-order smoke")
  })
})
