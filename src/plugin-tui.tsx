/** @jsxImportSource @opentui/solid */
/**
 * oh-my-pwn (OmP) — opencode TUI Plugin entry point.
 *
 * Server plugin (src/plugin.ts) 와 짝. 두 plugin 은 opencode 의 daemon/TUI
 * process 분리 모델 때문에 별개 entry. 통신 채널 = tree.json (server 가
 * atomic write, TUI 가 file watch). spec:
 * .omc/specs/deep-interview-tui-plugin-integration.md (Rev 3).
 *
 * T7: file watcher (dir 단위 + filename filter — atomic write inode 문제 회피)
 *     + JSON parse + Solid signal + reactive re-render.
 * T8-minimal: sidebar_content slot 에 "OmP — N active, M history" 텍스트.
 *     실제 tree JSX 는 T8 본격에서.
 */

import type { TuiPlugin } from "@opencode-ai/plugin/tui"
import { createMemo, createSignal } from "solid-js"
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

  // T8-minimal: sidebar_content slot. 실제 tree render 는 T8 본격에서.
  api.slots.register({
    order: 500,
    slots: {
      sidebar_content(_ctx) {
        const active = createMemo(() =>
          tree().nodes.filter((n) => !TERMINAL_STATUSES.includes(n.status)),
        )
        const history = createMemo(() =>
          tree().nodes.filter((n) => TERMINAL_STATUSES.includes(n.status)),
        )
        return (
          <box>
            <text>
              OmP — {active().length} active, {history().length} history
            </text>
          </box>
        )
      },
    },
  })
}

export default { tui: OmpTuiPlugin }
