/**
 * oh-my-pwn (OmP) — opencode TUI Plugin entry point.
 *
 * Server plugin (src/plugin.ts) 와 짝. 두 plugin 은 opencode 의 daemon/TUI
 * process 분리 모델 때문에 별개 entry. 통신 채널 = <challenge>/.omp/tree.json
 * (server 가 atomic write, TUI 가 file watch). spec:
 * .omc/specs/deep-interview-tui-plugin-integration.md
 *
 * T1 = skeleton entry. 실제 sidebar / tree render / mouse handler / keybind
 * 는 후속 task (T7-T14) 에서 박는다.
 */

import type { TuiPlugin } from "@opencode-ai/plugin/tui"

const OmpTuiPlugin: TuiPlugin = async (api, _options, _meta) => {
  // T1 skeleton — plugin lifecycle hook 등록만. UI 박힘 없음.
  // 후속 task 가 sidebar_content slot 등록, tree.json watcher, mouse handler,
  // keybind 를 여기에 추가.
  api.lifecycle.onDispose(() => {
    // cleanup hook 자리. 현재 박을 cleanup 없음.
  })
}

export default { tui: OmpTuiPlugin }
