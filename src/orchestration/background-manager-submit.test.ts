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

describe("BackgroundManager.resume (T38)", () => {
  test("resume re-prompts the session, returns to running, enables next submit", async () => {
    const prevDir = process.env.OMP_STATE_DIR
    const prevInst = process.env.OMP_INSTANCE_ID
    const stateDir = mkdtempSync(join(tmpdir(), "omp-state-"))
    const workDir = mkdtempSync(join(tmpdir(), "omp-work-"))
    process.env.OMP_STATE_DIR = stateDir
    process.env.OMP_INSTANCE_ID = "test-t38"

    const prompts: string[] = []
    try {
      const client: OmpSessionClient = {
        ...stubClient,
        promptAsync: async (params) => {
          const parts = (params.body as { parts?: Array<{ text?: string }> }).parts ?? []
          if (parts[0]?.text) prompts.push(parts[0].text)
          return {}
        },
      }
      const manager = new BackgroundManager({ client, directory: workDir, enableEventLog: true })
      const r = await manager.launchAsync({
        parentSessionID: "p",
        agent: "omp-exploiter-mode-1",
        description: "E",
        prompt: "attempt1",
      })

      manager.submitResult(r.session_id, { status: "failed" })
      await manager.waitAny([r.task_id]) // consume cycle 1

      const rr = await manager.resume(r.task_id, "attempt2")
      expect(rr.task_id).toBe(r.task_id)
      expect(manager.getTask(r.task_id)?.status).toBe("running")
      expect(prompts).toContain("attempt2") // session re-prompted with the follow-up

      // After resume the worker submits cycle 2 → wait returns the new result.
      manager.submitResult(r.session_id, { status: "success", flag: "DH{y}" })
      const o2 = await manager.waitAny([r.task_id])
      expect(o2.result).toEqual({ status: "success", flag: "DH{y}" })

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

  test("resume rejects unknown and terminal tasks", async () => {
    const dir = mkdtempSync(join(tmpdir(), "omp-work-"))
    try {
      const manager = new BackgroundManager({ client: stubClient, directory: dir })
      await expect(manager.resume("no-such-task", "x")).rejects.toThrow()

      const r = await manager.launchAsync({
        parentSessionID: "p",
        agent: "omp-exploiter-mode-1",
        description: "E",
        prompt: "go",
      })
      await manager.cancel(r.task_id)
      await expect(manager.resume(r.task_id, "again")).rejects.toThrow()
      manager.shutdown()
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe("BackgroundManager cancel (T40)", () => {
  test("cancel client.abort()s the session; terminate does not", async () => {
    const dir = mkdtempSync(join(tmpdir(), "omp-work-"))
    const aborted: string[] = []
    let sessionCounter = 0
    try {
      const client: OmpSessionClient = {
        ...stubClient,
        create: async () => ({ data: { id: `s${++sessionCounter}` } }),
        abort: async (params) => {
          aborted.push(params.path.id)
          return {}
        },
      }
      const manager = new BackgroundManager({ client, directory: dir })

      const r1 = await manager.launchAsync({
        parentSessionID: "p",
        agent: "omp-vulnhunter",
        description: "cancelled",
        prompt: "go",
      })
      await manager.cancel(r1.task_id)
      expect(manager.getTask(r1.task_id)?.status).toBe("cancelled")
      expect(aborted).toContain(r1.session_id) // cancel = emergency abort

      const r2 = await manager.launchAsync({
        parentSessionID: "p",
        agent: "omp-vulnhunter",
        description: "terminated",
        prompt: "go",
      })
      manager.terminate(r2.task_id)
      expect(manager.getTask(r2.task_id)?.status).toBe("terminated")
      expect(aborted).not.toContain(r2.session_id) // terminate = graceful, no abort

      manager.shutdown()
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test(
    "cancel works on an idle-awaiting worker (user hard stop)",
    async () => {
      const prevDir = process.env.OMP_STATE_DIR
      const prevInst = process.env.OMP_INSTANCE_ID
      const stateDir = mkdtempSync(join(tmpdir(), "omp-state-"))
      const workDir = mkdtempSync(join(tmpdir(), "omp-work-"))
      process.env.OMP_STATE_DIR = stateDir
      process.env.OMP_INSTANCE_ID = "test-t40"

      try {
        const client = { ...stubClient, status: async () => ({ x: { type: "idle" } }) }
        const manager = new BackgroundManager({ client, directory: workDir, enableEventLog: true })
        const r = await manager.launchAsync({
          parentSessionID: "p",
          agent: "omp-exploiter-mode-1",
          description: "E",
          prompt: "go",
        })
        manager.submitResult(r.session_id, { status: "failed" })
        await new Promise((res) => setTimeout(res, 3500)) // poll → idle-awaiting
        expect(manager.getTask(r.task_id)?.status).toBe("idle")

        // cancel is allowed on idle (T40) — a user-requested hard stop.
        expect(await manager.cancel(r.task_id)).toBe(true)
        expect(manager.getTask(r.task_id)?.status).toBe("cancelled")
        manager.shutdown()
      } finally {
        if (prevDir === undefined) delete process.env.OMP_STATE_DIR
        else process.env.OMP_STATE_DIR = prevDir
        if (prevInst === undefined) delete process.env.OMP_INSTANCE_ID
        else process.env.OMP_INSTANCE_ID = prevInst
        rmSync(stateDir, { recursive: true, force: true })
        rmSync(workDir, { recursive: true, force: true })
      }
    },
    10000,
  )
})

describe("BackgroundManager terminate (T39)", () => {
  test("parent-terminate marks terminated, idempotent, blocks resume", async () => {
    const dir = mkdtempSync(join(tmpdir(), "omp-work-"))
    try {
      const manager = new BackgroundManager({ client: stubClient, directory: dir })
      const r = await manager.launchAsync({
        parentSessionID: "p",
        agent: "omp-exploiter-mode-1",
        description: "E",
        prompt: "go",
      })
      expect(manager.terminate(r.task_id)).toBe(true)
      expect(manager.getTask(r.task_id)?.status).toBe("terminated")
      // Idempotent + unknown.
      expect(manager.terminate(r.task_id)).toBe(false)
      expect(manager.terminate("no-such-task")).toBe(false)
      // A terminated worker cannot be resumed.
      await expect(manager.resume(r.task_id, "x")).rejects.toThrow()
      manager.shutdown()
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test(
    "self-terminate event → poll marks the running task terminated",
    async () => {
      const prevDir = process.env.OMP_STATE_DIR
      const prevInst = process.env.OMP_INSTANCE_ID
      const stateDir = mkdtempSync(join(tmpdir(), "omp-state-"))
      const workDir = mkdtempSync(join(tmpdir(), "omp-work-"))
      process.env.OMP_STATE_DIR = stateDir
      process.env.OMP_INSTANCE_ID = "test-t39"

      try {
        const manager = new BackgroundManager({ client: stubClient, directory: workDir, enableEventLog: true })
        const r = await manager.launchAsync({
          parentSessionID: "p",
          agent: "omp-reverser",
          description: "R",
          prompt: "go",
        })
        // Child self-terminates (appends task_terminated for its session).
        manager.terminateSelf(r.session_id)
        // Poll tick (3s) detects the terminated event on the running task.
        await new Promise((res) => setTimeout(res, 3500))
        expect(manager.getTask(r.task_id)?.status).toBe("terminated")
        manager.shutdown()
      } finally {
        if (prevDir === undefined) delete process.env.OMP_STATE_DIR
        else process.env.OMP_STATE_DIR = prevDir
        if (prevInst === undefined) delete process.env.OMP_INSTANCE_ID
        else process.env.OMP_INSTANCE_ID = prevInst
        rmSync(stateDir, { recursive: true, force: true })
        rmSync(workDir, { recursive: true, force: true })
      }
    },
    10000,
  )
})

describe("BackgroundManager idle judgment (T37)", () => {
  test(
    "submit-then-idle → task marked idle (awaiting resume), not failed",
    async () => {
      const prevDir = process.env.OMP_STATE_DIR
      const prevInst = process.env.OMP_INSTANCE_ID
      const stateDir = mkdtempSync(join(tmpdir(), "omp-state-"))
      const workDir = mkdtempSync(join(tmpdir(), "omp-work-"))
      process.env.OMP_STATE_DIR = stateDir
      process.env.OMP_INSTANCE_ID = "test-t37"

      try {
        // status() reports the session (stubClient.create's id "x") as idle so
        // the poll hits the idle branch.
        const client = { ...stubClient, status: async () => ({ x: { type: "idle" } }) }
        const manager = new BackgroundManager({ client, directory: workDir, enableEventLog: true })
        const r = await manager.launchAsync({
          parentSessionID: "p",
          agent: "omp-exploiter-mode-1",
          description: "E",
          prompt: "go",
        })
        // Submit before the poll observes idle → idle means "awaiting resume".
        manager.submitResult(r.session_id, { status: "failed" })
        // Wait one poll tick (3s interval) for the idle judgment to run.
        await new Promise((res) => setTimeout(res, 3500))
        expect(manager.getTask(r.task_id)?.status).toBe("idle")
        manager.shutdown()
      } finally {
        if (prevDir === undefined) delete process.env.OMP_STATE_DIR
        else process.env.OMP_STATE_DIR = prevDir
        if (prevInst === undefined) delete process.env.OMP_INSTANCE_ID
        else process.env.OMP_INSTANCE_ID = prevInst
        rmSync(stateDir, { recursive: true, force: true })
        rmSync(workDir, { recursive: true, force: true })
      }
    },
    10000,
  )
})
