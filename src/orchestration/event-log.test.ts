/**
 * event-log 단위 테스트.
 *
 * 검증 영역:
 * - treeJsonDir/Path 의 env var 우선순위 (OMP_STATE_DIR > XDG_STATE_HOME > ~/.local/state/omp)
 * - initTreeJson — empty tree write, dir 자동 생성
 * - dumpTreeJson — atomic (tmp + rename), snapshot 정확성
 * - snapshotTasks — BackgroundTask Map → TreeJson 매핑 (parent_task_id resolution 포함)
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import {
  TREE_JSON_VERSION,
  dumpTreeJson,
  initTreeJson,
  orchestratorTaskId,
  snapshotTasks,
  treeJsonDir,
  treeJsonPath,
  type OrchestratorInfo,
} from "./event-log"
import type { BackgroundTask } from "./types"

const ORIG_OMP_STATE_DIR = process.env.OMP_STATE_DIR
const ORIG_XDG_STATE_HOME = process.env.XDG_STATE_HOME

function mkTempStateDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "omp-event-log-test-"))
  process.env.OMP_STATE_DIR = dir
  return dir
}

function restoreEnv(): void {
  if (ORIG_OMP_STATE_DIR === undefined) delete process.env.OMP_STATE_DIR
  else process.env.OMP_STATE_DIR = ORIG_OMP_STATE_DIR
  if (ORIG_XDG_STATE_HOME === undefined) delete process.env.XDG_STATE_HOME
  else process.env.XDG_STATE_HOME = ORIG_XDG_STATE_HOME
}

function mkTask(partial: Partial<BackgroundTask>): BackgroundTask {
  return {
    id: "t_default",
    parentSessionID: "parent_session",
    agent: "omp-vulnhunter",
    description: "test",
    prompt: "do work",
    status: "queued",
    createdAt: new Date("2026-01-01T00:00:00Z"),
    concurrencyKey: "omp-vulnhunter",
    ...partial,
  }
}

describe("treeJsonDir / treeJsonPath", () => {
  afterEach(() => restoreEnv())

  test("OMP_STATE_DIR override 가 최우선", () => {
    process.env.OMP_STATE_DIR = "/custom/omp/state"
    process.env.XDG_STATE_HOME = "/xdg"
    expect(treeJsonDir()).toBe("/custom/omp/state")
    expect(treeJsonPath()).toBe("/custom/omp/state/tree.json")
  })

  test("OMP_STATE_DIR 없으면 XDG_STATE_HOME/omp", () => {
    delete process.env.OMP_STATE_DIR
    process.env.XDG_STATE_HOME = "/xdg"
    expect(treeJsonDir()).toBe("/xdg/omp")
    expect(treeJsonPath()).toBe("/xdg/omp/tree.json")
  })

  test("env var 둘 다 없으면 ~/.local/state/omp", () => {
    delete process.env.OMP_STATE_DIR
    delete process.env.XDG_STATE_HOME
    const dir = treeJsonDir()
    expect(dir.endsWith("/.local/state/omp")).toBe(true)
  })
})

describe("initTreeJson", () => {
  let stateDir: string
  beforeEach(() => {
    stateDir = mkTempStateDir()
  })
  afterEach(() => {
    restoreEnv()
    rmSync(stateDir, { recursive: true, force: true })
  })

  test("dir 부재 시 자동 생성 + empty tree.json write", () => {
    rmSync(stateDir, { recursive: true, force: true })
    initTreeJson()
    expect(existsSync(treeJsonPath())).toBe(true)
    const content = JSON.parse(readFileSync(treeJsonPath(), "utf-8"))
    expect(content.version).toBe(TREE_JSON_VERSION)
    expect(content.nodes).toEqual([])
    expect(typeof content.updated_at).toBe("string")
  })

  test("이전 tree.json 덮어쓰기", () => {
    mkdirSync(stateDir, { recursive: true })
    initTreeJson()
    // 첫 write
    const first = JSON.parse(readFileSync(treeJsonPath(), "utf-8"))
    // 두 번째 init — updated_at 갱신
    initTreeJson()
    const second = JSON.parse(readFileSync(treeJsonPath(), "utf-8"))
    expect(second.nodes).toEqual([])
    // updated_at 은 두 번째가 같거나 더 늦음
    expect(Date.parse(second.updated_at)).toBeGreaterThanOrEqual(Date.parse(first.updated_at))
  })
})

describe("snapshotTasks", () => {
  test("빈 Map → empty nodes", () => {
    const result = snapshotTasks(new Map())
    expect(result.version).toBe(TREE_JSON_VERSION)
    expect(result.nodes).toEqual([])
  })

  test("BackgroundTask → TreeNode 필드 매핑", () => {
    const tasks = new Map<string, BackgroundTask>()
    tasks.set("t1", mkTask({
      id: "t1",
      sessionID: "s1",
      parentSessionID: "parent_session",
      agent: "omp-vulnhunter",
      status: "running",
      startedAt: new Date("2026-01-01T00:01:00Z"),
    }))
    const result = snapshotTasks(tasks)
    expect(result.nodes).toHaveLength(1)
    const node = result.nodes[0]
    expect(node.task_id).toBe("t1")
    expect(node.session_id).toBe("s1")
    expect(node.role).toBe("omp-vulnhunter")
    expect(node.parent_task_id).toBeNull() // parent_session not in tasks map
    expect(node.status).toBe("running")
    expect(node.started_at).toBe("2026-01-01T00:01:00.000Z")
    expect(node.ended_at).toBeUndefined()
  })

  test("parent_task_id resolution — parent 의 sessionID 가 다른 task 의 sessionID 와 매치", () => {
    const tasks = new Map<string, BackgroundTask>()
    tasks.set("orch", mkTask({
      id: "orch",
      sessionID: "s_orch",
      parentSessionID: "top_level",
      agent: "omp-orchestrator",
      status: "running",
    }))
    tasks.set("vh1", mkTask({
      id: "vh1",
      sessionID: "s_vh1",
      parentSessionID: "s_orch", // orch 의 sessionID
      agent: "omp-vulnhunter",
      status: "running",
    }))
    const result = snapshotTasks(tasks)
    const vh1Node = result.nodes.find(n => n.task_id === "vh1")
    expect(vh1Node?.parent_task_id).toBe("orch")
    const orchNode = result.nodes.find(n => n.task_id === "orch")
    expect(orchNode?.parent_task_id).toBeNull()
  })

  test("terminal status 일 때 ended_at 박힘", () => {
    const tasks = new Map<string, BackgroundTask>()
    tasks.set("t1", mkTask({
      id: "t1",
      sessionID: "s1",
      status: "completed",
      startedAt: new Date("2026-01-01T00:01:00Z"),
      completedAt: new Date("2026-01-01T00:05:00Z"),
    }))
    const result = snapshotTasks(tasks)
    expect(result.nodes[0].ended_at).toBe("2026-01-01T00:05:00.000Z")
  })

  test("startedAt 없으면 createdAt fallback", () => {
    const tasks = new Map<string, BackgroundTask>()
    tasks.set("t_queued", mkTask({
      id: "t_queued",
      status: "queued",
      createdAt: new Date("2026-01-01T00:00:00Z"),
      // startedAt undefined
    }))
    const result = snapshotTasks(tasks)
    expect(result.nodes[0].started_at).toBe("2026-01-01T00:00:00.000Z")
  })

  test("orchestrator root 박힘 — task_id sentinel + challenge_name + parent_task_id null", () => {
    const tasks = new Map<string, BackgroundTask>()
    const orchestrators = new Map<string, OrchestratorInfo>()
    orchestrators.set("s_orch", {
      sessionID: "s_orch",
      agent: "omp-orchestrator",
      challengeName: "afterimage",
      startedAt: new Date("2026-01-01T00:00:00Z"),
    })
    const result = snapshotTasks(tasks, orchestrators)
    expect(result.nodes).toHaveLength(1)
    const root = result.nodes[0]
    expect(root.task_id).toBe(orchestratorTaskId("s_orch"))
    expect(root.session_id).toBe("s_orch")
    expect(root.role).toBe("omp-orchestrator")
    expect(root.parent_task_id).toBeNull()
    expect(root.status).toBe("running")
    expect(root.challenge_name).toBe("afterimage")
    expect(root.started_at).toBe("2026-01-01T00:00:00.000Z")
  })

  test("sub-agent 의 parentSessionID 가 orchestrator session 매치 — parent_task_id = sentinel", () => {
    const tasks = new Map<string, BackgroundTask>()
    tasks.set("vh1", mkTask({
      id: "vh1",
      sessionID: "s_vh1",
      parentSessionID: "s_orch", // orchestrator session
      agent: "omp-vulnhunter",
      status: "running",
    }))
    const orchestrators = new Map<string, OrchestratorInfo>()
    orchestrators.set("s_orch", {
      sessionID: "s_orch",
      agent: "omp-orchestrator",
      challengeName: "afterimage",
      startedAt: new Date("2026-01-01T00:00:00Z"),
    })
    const result = snapshotTasks(tasks, orchestrators)
    expect(result.nodes).toHaveLength(2)
    const vh1 = result.nodes.find((n) => n.task_id === "vh1")
    expect(vh1?.parent_task_id).toBe(orchestratorTaskId("s_orch"))
  })

  test("multi-challenge — orchestrator 여러 개 각자 별개 root", () => {
    const tasks = new Map<string, BackgroundTask>()
    const orchestrators = new Map<string, OrchestratorInfo>()
    orchestrators.set("s_orch_a", {
      sessionID: "s_orch_a",
      agent: "omp-orchestrator",
      challengeName: "afterimage",
      startedAt: new Date("2026-01-01T00:00:00Z"),
    })
    orchestrators.set("s_orch_b", {
      sessionID: "s_orch_b",
      agent: "omp-orchestrator",
      challengeName: "sleepy_booth",
      startedAt: new Date("2026-01-01T00:30:00Z"),
    })
    const result = snapshotTasks(tasks, orchestrators)
    expect(result.nodes).toHaveLength(2)
    const names = result.nodes.map((n) => n.challenge_name).sort()
    expect(names).toEqual(["afterimage", "sleepy_booth"])
  })
})

describe("dumpTreeJson", () => {
  let stateDir: string
  beforeEach(() => {
    stateDir = mkTempStateDir()
  })
  afterEach(() => {
    restoreEnv()
    rmSync(stateDir, { recursive: true, force: true })
  })

  test("atomic write — partial-read 불가 (tmp 잔여 없음)", () => {
    const tasks = new Map<string, BackgroundTask>()
    tasks.set("t1", mkTask({ id: "t1", sessionID: "s1", status: "running" }))
    dumpTreeJson(tasks)
    expect(existsSync(treeJsonPath())).toBe(true)
    expect(existsSync(`${treeJsonPath()}.tmp`)).toBe(false)
  })

  test("write 후 read 시 정확한 schema", () => {
    const tasks = new Map<string, BackgroundTask>()
    tasks.set("t1", mkTask({
      id: "t1",
      sessionID: "s1",
      status: "running",
      startedAt: new Date("2026-01-01T00:01:00Z"),
    }))
    dumpTreeJson(tasks)
    const content = JSON.parse(readFileSync(treeJsonPath(), "utf-8"))
    expect(content.version).toBe(TREE_JSON_VERSION)
    expect(content.nodes).toHaveLength(1)
    expect(content.nodes[0].task_id).toBe("t1")
  })

  test("write 실패 시 throw 안 함 (best-effort)", () => {
    // /dev/null 같은 invalid dir 박아서 강제 실패
    process.env.OMP_STATE_DIR = "/dev/null/cannot-mkdir-here"
    expect(() => dumpTreeJson(new Map())).not.toThrow()
  })
})
