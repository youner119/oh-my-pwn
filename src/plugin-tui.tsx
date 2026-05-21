/** @jsxImportSource @opentui/solid */
/**
 * oh-my-pwn (OmP) — opencode TUI Plugin entry point.
 *
 * Server plugin (src/plugin.ts) 와 짝. 두 plugin 은 opencode 의 daemon/TUI
 * process 분리 모델 때문에 별개 entry. 통신 채널 = tree.json (server 가
 * atomic write, TUI 가 file watch). spec:
 * .omc/specs/deep-interview-tui-plugin-integration.md (Rev 4).
 *
 * Phase 1 박힘 (T7 + T8/T9/T10):
 * - file watcher (dir 단위 + filename filter — atomic write inode 회피)
 * - Solid signal + reactive re-render
 * - sidebar 3-section: dashboard + active tree (hierarchical + chevron) + history flat
 */

import type { TuiPlugin } from "@opencode-ai/plugin/tui"
import { createMemo, createSignal, For, Show } from "solid-js"
import { existsSync, readFileSync, watch as fsWatch } from "node:fs"
import { dirname } from "node:path"

import {
  TREE_JSON_VERSION,
  treeJsonPath,
  type TreeJson,
  type TreeNode,
} from "./orchestration/tree-dump"

const TERMINAL_STATUSES: TreeNode["status"][] = [
  "completed",
  "failed",
  "cancelled",
]

function isTerminal(status: TreeNode["status"]): boolean {
  return TERMINAL_STATUSES.includes(status)
}

function emptyTree(): TreeJson {
  return {
    version: TREE_JSON_VERSION,
    updated_at: new Date().toISOString(),
    nodes: [],
  }
}

function readTreeSafe(path: string): TreeJson {
  try {
    if (!existsSync(path)) return emptyTree()
    const content = readFileSync(path, "utf-8")
    return JSON.parse(content) as TreeJson
  } catch (err) {
    console.error(`[plugin-tui] read tree.json failed: ${String(err)}`)
    return emptyTree()
  }
}

/** ms → human-friendly elapsed (Xs / Xm Ys / Xh Ym). */
function formatElapsed(ms: number): string {
  if (ms < 0) return "0s"
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ${s % 60}s`
  const h = Math.floor(m / 60)
  return `${h}h ${m % 60}m`
}

/** ISO 8601 → ms since (now - parsed). 음수 보호. */
function elapsedSince(iso: string): number {
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return 0
  return Math.max(0, Date.now() - t)
}

/** role 의 prefix "omp-" 제거해서 짧은 label. */
function shortRole(role: string): string {
  return role.startsWith("omp-") ? role.slice(4) : role
}

/** -------- Dashboard (상단 박스) -------- */
function Dashboard(props: { tree: () => TreeJson }) {
  const allNodes = createMemo(() => props.tree().nodes)
  const active = createMemo(() => allNodes().filter((n) => !isTerminal(n.status)))
  const history = createMemo(() => allNodes().filter((n) => isTerminal(n.status)))
  // Root = parent_task_id null. 가장 오래된 active root 의 started_at 기준 elapsed.
  const oldestActiveRoot = createMemo(() => {
    const roots = allNodes().filter(
      (n) => n.parent_task_id === null && !isTerminal(n.status),
    )
    if (roots.length === 0) return undefined
    return roots.reduce((oldest, n) =>
      Date.parse(n.started_at) < Date.parse(oldest.started_at) ? n : oldest,
    )
  })
  const challengeLabel = createMemo(() => {
    const root = oldestActiveRoot()
    return root?.challenge_name ?? ""
  })
  const elapsedLabel = createMemo(() => {
    const root = oldestActiveRoot()
    if (!root) return ""
    return formatElapsed(elapsedSince(root.started_at))
  })

  return (
    <box>
      <text>
        <b>OmP</b>
        <Show when={challengeLabel()}>
          {" — "}
          {challengeLabel()}
        </Show>
      </text>
      <text>
        {active().length} active, {history().length} history
      </text>
      <Show when={elapsedLabel()}>
        <text>{elapsedLabel()}</text>
      </Show>
    </box>
  )
}

/** -------- Active tree (recursive) -------- */
function ActiveTreeNode(props: {
  node: TreeNode
  allActive: () => TreeNode[]
  collapsed: () => Set<string>
  toggle: (taskId: string) => void
  navigate: (sessionID: string | undefined) => void
  depth: number
}) {
  const children = createMemo(() =>
    props.allActive().filter((n) => n.parent_task_id === props.node.task_id),
  )
  const hasChildren = createMemo(() => children().length > 0)
  const isCollapsed = createMemo(() => props.collapsed().has(props.node.task_id))
  const indent = "  ".repeat(props.depth)
  const elapsedStr = createMemo(() =>
    formatElapsed(elapsedSince(props.node.started_at)),
  )

  return (
    <box>
      <box flexDirection="row" gap={1}>
        <Show when={hasChildren()}>
          <box
            onMouseDown={(e) => {
              e.stopPropagation()
              props.toggle(props.node.task_id)
            }}
          >
            <text>
              {indent}
              {isCollapsed() ? "▶" : "▼"}
            </text>
          </box>
        </Show>
        <box
          flexGrow={1}
          onMouseDown={(e) => {
            e.stopPropagation()
            props.navigate(props.node.session_id)
          }}
        >
          <text>
            <Show when={!hasChildren()}>
              {indent}
              {"  "}
            </Show>
            {shortRole(props.node.role)}
            <Show when={hasChildren() && isCollapsed()}>
              {" ("}
              {children().length}
              {")"}
            </Show>
            {" ["}
            {props.node.status} {elapsedStr()}
            {"]"}
          </text>
        </box>
      </box>
      <Show when={hasChildren() && !isCollapsed()}>
        <For each={children()}>
          {(child) => (
            <ActiveTreeNode
              node={child}
              allActive={props.allActive}
              collapsed={props.collapsed}
              toggle={props.toggle}
              navigate={props.navigate}
              depth={props.depth + 1}
            />
          )}
        </For>
      </Show>
    </box>
  )
}

function ActiveTree(props: {
  tree: () => TreeJson
  collapsed: () => Set<string>
  toggle: (taskId: string) => void
  navigate: (sessionID: string | undefined) => void
}) {
  const allActive = createMemo(() =>
    props.tree().nodes.filter((n) => !isTerminal(n.status)),
  )
  const roots = createMemo(() =>
    allActive().filter((n) => n.parent_task_id === null),
  )
  return (
    <box>
      <For each={roots()}>
        {(root) => (
          <ActiveTreeNode
            node={root}
            allActive={allActive}
            collapsed={props.collapsed}
            toggle={props.toggle}
            navigate={props.navigate}
            depth={0}
          />
        )}
      </For>
    </box>
  )
}

/** -------- History flat list -------- */
function HistorySection(props: {
  tree: () => TreeJson
  navigate: (sessionID: string | undefined) => void
}) {
  const history = createMemo(() => {
    const items = props.tree().nodes.filter((n) => isTerminal(n.status))
    // 시간순 — 가장 최근 종료가 위.
    return items.sort((a, b) => {
      const ta = a.ended_at ? Date.parse(a.ended_at) : 0
      const tb = b.ended_at ? Date.parse(b.ended_at) : 0
      return tb - ta
    })
  })
  function totalDuration(n: TreeNode): string {
    if (!n.ended_at) return formatElapsed(elapsedSince(n.started_at))
    const start = Date.parse(n.started_at)
    const end = Date.parse(n.ended_at)
    return formatElapsed(Math.max(0, end - start))
  }
  return (
    <Show when={history().length > 0}>
      <box>
        <text>── History ──</text>
        <scrollbox stickyScroll stickyStart="top">
          <For each={history()}>
            {(node) => (
              <box onMouseDown={() => props.navigate(node.session_id)}>
                <text>
                  {shortRole(node.role)} [{node.status} {totalDuration(node)}]
                </text>
              </box>
            )}
          </For>
        </scrollbox>
      </box>
    </Show>
  )
}

/** -------- Sidebar root -------- */
function OmpSidebarView(props: {
  tree: () => TreeJson
  navigate: (sessionID: string | undefined) => void
}) {
  // chevron expand/collapse state — taskId set (collapsed = present). plugin
  // lifecycle 한정 (재시작 시 reset, all expanded by default). spec D-T8-3.
  const [collapsed, setCollapsed] = createSignal<Set<string>>(new Set())
  function toggle(taskId: string): void {
    setCollapsed((prev) => {
      const next = new Set(prev)
      if (next.has(taskId)) next.delete(taskId)
      else next.add(taskId)
      return next
    })
  }

  return (
    <box>
      <Dashboard tree={props.tree} />
      <ActiveTree
        tree={props.tree}
        collapsed={collapsed}
        toggle={toggle}
        navigate={props.navigate}
      />
      <HistorySection tree={props.tree} navigate={props.navigate} />
    </box>
  )
}

const OmpTuiPlugin: TuiPlugin = async (api, _options, _meta) => {
  const path = treeJsonPath()
  const watchDir = dirname(path)
  const watchFilename = "tree.json"

  const [tree, setTree] = createSignal<TreeJson>(readTreeSafe(path))

  // dir 단위 watch + filename filter — atomic write (rename) 의 inode 교체로
  // 인한 fs.watch 미감지 문제 회피. dir 안 다른 file event 는 filter 로 drop.
  let watcher: ReturnType<typeof fsWatch> | undefined
  try {
    watcher = fsWatch(watchDir, (_event, filename) => {
      if (filename === watchFilename) {
        setTree(readTreeSafe(path))
      }
    })
  } catch (err) {
    console.error(`[plugin-tui] watcher start failed: ${String(err)}`)
  }

  api.lifecycle.onDispose(() => {
    watcher?.close()
  })

  function navigate(sessionID: string | undefined): void {
    if (!sessionID) return
    try {
      api.route.navigate("session", { sessionID })
    } catch (err) {
      console.error(`[plugin-tui] route.navigate failed: ${String(err)}`)
    }
  }

  // order 50 = 내장 sidebar plugin 보다 위. OmP tree 가 사용자 주 view.
  api.slots.register({
    order: 50,
    slots: {
      sidebar_content(_ctx) {
        return <OmpSidebarView tree={tree} navigate={navigate} />
      },
    },
  })
}

// id 필수 — file plugin 의 경우 opencode loader 가 module.id 로 plugin id 결정.
// 출처: opencode/specs/tui-plugins.md.
export default { id: "omp", tui: OmpTuiPlugin }
