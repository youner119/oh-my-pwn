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

describe("BackgroundManager wait resolves on submit (T36, D + consumed)", () => {
  /**
   * Full submit→wait→result→consumed chain. Requires a real events.log
   * (enableEventLog + temp OMP_STATE_DIR) since submit detection is via
   * events.log fold (cross-closure). Uses a fixed OMP_INSTANCE_ID so the
   * events file path is deterministic.
   */
  test("wait_any returns the submitted result, then consumes it (multi-submit)", async () => {
    const prevDir = process.env.OMP_STATE_DIR
    const prevInst = process.env.OMP_INSTANCE_ID
    const stateDir = mkdtempSync(join(tmpdir(), "omp-state-"))
    const workDir = mkdtempSync(join(tmpdir(), "omp-work-"))
    process.env.OMP_STATE_DIR = stateDir
    process.env.OMP_INSTANCE_ID = "test-t36"

    try {
      const client = { ...stubClient }
      const manager = new BackgroundManager({ client, directory: workDir, enableEventLog: true })
      const r = await manager.launchAsync({
        parentSessionID: "p",
        agent: "omp-exploiter-mode-1",
        description: "E",
        prompt: "go",
      })

      // Child submits attempt 1 (cycle 1) — parent wait should return it.
      manager.submitResult(r.session_id, { status: "failed", reason: "no leak" })
      const o1 = await manager.waitAny([r.task_id])
      expect(o1.task_id).toBe(r.task_id)
      expect(o1.result).toEqual({ status: "failed", reason: "no leak" })
      expect(o1.result_path).toContain("submissions")

      // Child submits attempt 2 (cycle 2) after a resume — wait must return the
      // NEW submit, not re-resolve the already-consumed cycle 1 (stale guard).
      manager.submitResult(r.session_id, { status: "success", flag: "DH{x}" })
      const o2 = await manager.waitAny([r.task_id])
      expect(o2.result).toEqual({ status: "success", flag: "DH{x}" })

      manager.shutdown()
    } finally {
      if (prevDir === undefined) delete process.env.OMP_STATE_DIR
      else process.env.OMP_STATE_DIR = prevDir
      if (prevInst === undefined) delete process.env.OMP_INSTANCE_ID
      else process.env.OMP_INSTANCE_ID = prevInst
      rmSync(stateDir, { recursive: true, force: true })
      rmSync(workDir, { recursive: true, force: true })
    }
  })
})
