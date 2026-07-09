import { describe, expect, test } from "bun:test"
import { mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { BackgroundManager } from "./background-manager"
import type { OmpSessionClient } from "./types"

/** Minimal client stub — submitResult touches no client methods (pure fs). */
const stubClient: OmpSessionClient = {
  create: async () => ({ data: { id: "x" } }),
  promptAsync: async () => ({}),
  status: async () => ({}),
  messages: async () => ({ data: [] }),
  get: async () => ({ data: {} }),
  abort: async () => ({}),
}

function withManager(fn: (m: BackgroundManager, dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "omp-submit-"))
  // enableEventLog defaults false → appendEvent is a no-op (no events.log write).
  const manager = new BackgroundManager({ client: stubClient, directory: dir })
  try {
    fn(manager, dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

describe("BackgroundManager.submitResult (T35)", () => {
  test("first submit → cycle 1, pretty-printed JSON at expected path", () => {
    withManager((m, dir) => {
      const r = m.submitResult("ses_A", { candidates: [1, 2] })
      expect(r.cycle).toBe(1)
      expect(r.result_path).toBe(join(dir, ".omp", "submissions", "ses_A-1.json"))

      const content = readFileSync(r.result_path, "utf-8")
      expect(JSON.parse(content)).toEqual({ candidates: [1, 2] })
      // Pretty-printed (multi-line) so Read's per-line char cap is not hit.
      expect(content).toContain("\n")
    })
  })

  test("multi-submit increments cycle per session (file-count based)", () => {
    withManager((m) => {
      expect(m.submitResult("ses_A", { a: 1 }).cycle).toBe(1)
      expect(m.submitResult("ses_A", { a: 2 }).cycle).toBe(2)
      expect(m.submitResult("ses_A", { a: 3 }).cycle).toBe(3)
    })
  })

  test("cycle is isolated per session", () => {
    withManager((m) => {
      expect(m.submitResult("ses_A", {}).cycle).toBe(1)
      expect(m.submitResult("ses_B", {}).cycle).toBe(1)
      expect(m.submitResult("ses_A", {}).cycle).toBe(2)
    })
  })

  test("cycle persists across a fresh manager (survives closure reload)", () => {
    // Simulates a parent-instance reload: a new manager over the same dir must
    // continue the cycle count from existing files (file-count, not in-memory).
    const dir = mkdtempSync(join(tmpdir(), "omp-submit-"))
    try {
      const m1 = new BackgroundManager({ client: stubClient, directory: dir })
      expect(m1.submitResult("ses_A", {}).cycle).toBe(1)
      const m2 = new BackgroundManager({ client: stubClient, directory: dir })
      expect(m2.submitResult("ses_A", {}).cycle).toBe(2)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
