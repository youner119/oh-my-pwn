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

/** Track all top-level right-column pane IDs for even-split layout. */
let rightColumnPaneIds: string[] = []

/** Serialize pane creation to prevent race conditions. */
let paneCreationQueue: Promise<unknown> = Promise.resolve()

/** Reset pane tracking (call on shutdown or when all panes closed). */
export function resetPaneTracking(): void {
  lastRightPaneId = undefined
  rightColumnPaneIds = []
  paneCreationQueue = Promise.resolve()
}

/**
 * Spawn a tmux pane that attaches to a sub-agent session.
 *
 * Layout rules:
 * - First top-level agent: vertical split (-h) → creates right column
 * - Additional top-level agents: horizontal split (-v) in right column
 * - After each top-level pane creation, re-layout the right column with
 *   even-vertical so all panes get equal height (n-등분).
 * - Child of an agent with a pane (e.g., Exploiter of SA): vertical split (-h)
 *   of parent's pane → appears to the right of its parent.
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
      if (!parentPaneId) {
        lastRightPaneId = paneId
        rightColumnPaneIds.push(paneId)
        // Re-layout right column panes to equal height after each addition
        await rebalanceRightColumn()
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
 * Rebalance right-column panes to equal height.
 * Uses tmux resize-pane with percentage to achieve n-등분.
 */
async function rebalanceRightColumn(): Promise<void> {
  const count = rightColumnPaneIds.length
  if (count < 2) return

  try {
    // Get the total height of the right column from the first pane's window
    const heightProc = Bun.spawn(
      ["tmux", "display-message", "-t", rightColumnPaneIds[0], "-p", "#{window_height}"],
      { stdout: "pipe", stderr: "ignore" },
    )
    const windowHeight = parseInt((await new Response(heightProc.stdout).text()).trim(), 10)
    await heightProc.exited
    if (!windowHeight || isNaN(windowHeight)) return

    const targetHeight = Math.floor(windowHeight / count)

    // Resize each pane except the last (last takes remaining space)
    for (let i = 0; i < count - 1; i++) {
      Bun.spawn(
        ["tmux", "resize-pane", "-t", rightColumnPaneIds[i], "-y", String(targetHeight)],
        { stdout: "ignore", stderr: "ignore" },
      )
    }
  } catch {
    // Non-critical — layout will just be slightly uneven
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
