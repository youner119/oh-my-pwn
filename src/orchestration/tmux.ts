/**
 * tmux utilities for sub-agent pane spawning.
 *
 * Layout strategy:
 * - First sub-agent: vertical split (-h) → right pane created
 * - Subsequent sub-agents: horizontal split (-v) of the last right pane
 *   → stacks sub-agents vertically on the right side
 *
 * ```
 * ┌──────────────┬──────────────┐
 * │              │  sub-agent 1 │
 * │ Orchestrator ├──────────────┤
 * │   (main)     │  sub-agent 2 │
 * │              ├──────────────┤
 * │              │  sub-agent 3 │
 * └──────────────┴──────────────┘
 * ```
 *
 * Sub-agent sessions can also be viewed via Ctrl+X / arrow keys in
 * the opencode TUI without tmux panes.
 */

/** Check if the current process is running inside a tmux session. */
export function isInsideTmux(): boolean {
  return Boolean(process.env.TMUX)
}

/** Get the current tmux pane ID. */
export function getCurrentPaneId(): string | undefined {
  return process.env.TMUX_PANE
}

/** Track the last right-side pane for stacking layout. */
let lastRightPaneId: string | undefined

/** Serialize pane creation to prevent race conditions on lastRightPaneId. */
let paneCreationQueue: Promise<unknown> = Promise.resolve()

/** Reset pane tracking (call on shutdown). */
export function resetPaneTracking(): void {
  lastRightPaneId = undefined
  paneCreationQueue = Promise.resolve()
}

/**
 * Spawn a tmux pane that attaches to a sub-agent session.
 *
 * Layout rules:
 * - First top-level agent: vertical split (-h) → creates right column
 * - Additional top-level agents: horizontal split (-v) in right column → stack
 * - Child of an agent with a pane (e.g., Exploiter of SA): vertical split (-h)
 *   of parent's pane → appears to the right of its parent
 *
 * @param parentPaneId — if the parent session has a tmux pane, split it
 *   horizontally to place this agent to its right.
 */
export async function spawnSubagentPane(options: {
  serverUrl: string
  sessionId: string
  title: string
  parentPaneId?: string
}): Promise<string | undefined> {
  // Serialize pane creation to prevent race conditions on lastRightPaneId.
  // Without this, concurrent launchAll/launchPool calls all read
  // lastRightPaneId as undefined and every agent does -h (left/right split).
  const result = paneCreationQueue.then(() => doSpawnPane(options))
  paneCreationQueue = result.catch(() => {})
  return result
}

async function doSpawnPane(options: {
  serverUrl: string
  sessionId: string
  title: string
  parentPaneId?: string
}): Promise<string | undefined> {
  const { serverUrl, sessionId, title, parentPaneId } = options

  const cleanUrl = serverUrl.replace(/\/+$/u, "")
  const xdgConfigHome = process.env.XDG_CONFIG_HOME || ""
  const shell = process.env.SHELL || "/bin/sh"
  const envPrefix = xdgConfigHome ? `XDG_CONFIG_HOME=${xdgConfigHome}` : ""
  const attachCmd = `${envPrefix} opencode attach ${cleanUrl} --session ${sessionId}`

  let splitArgs: string[]

  if (parentPaneId) {
    // Child agent (e.g., Exploiter) → split parent's pane to the right
    splitArgs = ["-h", "-d", "-P", "-F", "#{pane_id}", "-t", parentPaneId]
  } else if (!lastRightPaneId) {
    // First top-level agent → vertical split (create right column)
    splitArgs = ["-h", "-d", "-P", "-F", "#{pane_id}"]
  } else {
    // Additional top-level agent → stack in right column
    splitArgs = ["-v", "-d", "-P", "-F", "#{pane_id}", "-t", lastRightPaneId]
  }

  try {
    const proc = Bun.spawn(
      ["tmux", "split-window", ...splitArgs, shell, "-c", attachCmd],
      { stdout: "pipe", stderr: "pipe" },
    )

    const paneId = (await new Response(proc.stdout).text()).trim()
    await proc.exited

    if (paneId) {
      // Only track top-level panes for the right-column stacking layout.
      // Child panes (Exploiter next to SA) don't affect the column layout.
      if (!parentPaneId) {
        lastRightPaneId = paneId
      }

      const shortTitle = title.slice(0, 30)
      Bun.spawn(
        ["tmux", "select-pane", "-t", paneId, "-T", `omp: ${shortTitle}`],
        { stdout: "ignore", stderr: "ignore" },
      )
      Bun.spawn(
        ["tmux", "set-option", "-t", paneId, "remain-on-exit", "on"],
        { stdout: "ignore", stderr: "ignore" },
      )
    }

    return paneId || undefined
  } catch {
    return undefined
  }
}

/**
 * Close a tmux pane by ID.
 */
export async function closeTmuxPane(paneId: string): Promise<void> {
  try {
    const proc = Bun.spawn(
      ["tmux", "kill-pane", "-t", paneId],
      { stdout: "ignore", stderr: "ignore" },
    )
    await proc.exited
  } catch {
    // Pane might already be closed
  }
}
