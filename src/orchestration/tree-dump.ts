/**
 * tree.json — TUI plugin 이 watch 하는 agent tree snapshot.
 *
 * Spec: .omc/specs/deep-interview-tui-plugin-integration.md (T4-T6, D2 정정).
 *
 * 위치: `$OMP_STATE_DIR ?? $XDG_STATE_HOME/omp ?? ~/.local/state/omp` 안 `tree.json`.
 * challenge 디렉토리 분리 폐기 (D2 정정 from Rev 2) — single global location,
 * plugin load 시점에 초기화.
 *
 * Write protocol: atomic (`tmp` + `rename`). `src/state/io.ts:saveChallengeState`
 * 와 일치 패턴. partial-read 불가.
 *
 * Failure handling: best-effort. dump 실패가 primary 흐름 (sub-agent spawn)
 * 막지 않음 — try/catch + console.error.
 */

import { existsSync, mkdirSync, renameSync, writeFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

import type { BackgroundTask, TaskStatus } from "./types"

/** Schema version. Bump when breaking. */
export const TREE_JSON_VERSION = 1

export interface TreeNode {
  task_id: string
  session_id?: string
  role: string
  /** Parent task id. null = parent 가 BackgroundManager 가 추적 안 하는 top-level session (예: Orchestrator). */
  parent_task_id: string | null
  status: TaskStatus
  /** ISO 8601. startedAt 없으면 createdAt fallback. */
  started_at: string
  /** ISO 8601. status 가 terminal (completed/failed/cancelled) 일 때만 set. */
  ended_at?: string
}

export interface TreeJson {
  version: number
  /** ISO 8601 — snapshot 시각. */
  updated_at: string
  nodes: TreeNode[]
}

/**
 * tree.json 디렉토리 resolve.
 *
 * 우선순위:
 *   1. `OMP_STATE_DIR` env var (사용자 override)
 *   2. `$XDG_STATE_HOME/omp`
 *   3. `~/.local/state/omp` (XDG 표준 fallback)
 */
export function treeJsonDir(): string {
  const override = process.env.OMP_STATE_DIR
  if (override) return override
  const xdg = process.env.XDG_STATE_HOME
  if (xdg) return join(xdg, "omp")
  return join(homedir(), ".local", "state", "omp")
}

/** tree.json 의 절대 경로. */
export function treeJsonPath(): string {
  return join(treeJsonDir(), "tree.json")
}

/**
 * Snapshot the current task map to a TreeJson payload.
 *
 * Maps BackgroundTask fields to schema:
 * - `id` → `task_id`
 * - `sessionID` → `session_id`
 * - `agent` → `role`
 * - `parentSessionID` → `parent_task_id` (sessionID 로 lookup; 못 찾으면 null)
 * - `status` → `status`
 * - `startedAt ?? createdAt` → `started_at`
 * - `completedAt` → `ended_at` (있을 때만)
 */
export function snapshotTasks(tasks: Map<string, BackgroundTask>): TreeJson {
  // sessionID → taskID lookup for parent resolution.
  const sessionToTask = new Map<string, string>()
  for (const task of tasks.values()) {
    if (task.sessionID) sessionToTask.set(task.sessionID, task.id)
  }

  const nodes: TreeNode[] = []
  for (const task of tasks.values()) {
    const startedAt = task.startedAt ?? task.createdAt
    const node: TreeNode = {
      task_id: task.id,
      session_id: task.sessionID,
      role: task.agent,
      parent_task_id: sessionToTask.get(task.parentSessionID) ?? null,
      status: task.status,
      started_at: startedAt.toISOString(),
    }
    if (task.completedAt) {
      node.ended_at = task.completedAt.toISOString()
    }
    nodes.push(node)
  }

  return {
    version: TREE_JSON_VERSION,
    updated_at: new Date().toISOString(),
    nodes,
  }
}

function ensureDir(dir: string): void {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
}

function atomicWrite(path: string, content: string): void {
  const tmpPath = `${path}.tmp`
  writeFileSync(tmpPath, content, "utf-8")
  renameSync(tmpPath, path)
}

/**
 * tree.json 을 빈 (nodes: []) 상태로 초기화.
 *
 * Plugin load 시점에 호출. 이전 세션의 잔여 tree 가 sidebar 에 보이지 않게.
 * 디렉토리 부재 시 mkdir.
 */
export function initTreeJson(): void {
  ensureDir(treeJsonDir())
  const empty: TreeJson = {
    version: TREE_JSON_VERSION,
    updated_at: new Date().toISOString(),
    nodes: [],
  }
  atomicWrite(treeJsonPath(), `${JSON.stringify(empty, null, 2)}\n`)
}

/**
 * tree.json 에 snapshot 박음. atomic.
 *
 * BackgroundManager 의 state transition 마다 호출. 실패는 console.error 만
 * (primary 흐름 막지 않음).
 */
export function dumpTreeJson(tasks: Map<string, BackgroundTask>): void {
  try {
    ensureDir(treeJsonDir())
    const payload = snapshotTasks(tasks)
    atomicWrite(treeJsonPath(), `${JSON.stringify(payload, null, 2)}\n`)
  } catch (err) {
    console.error(`[tree-dump] write failed: ${String(err)}`)
  }
}
