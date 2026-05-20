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
      // Tag the pane with its session_id so a different BackgroundManager
      // instance (e.g. an SA spawning an Exploiter from its own plugin
      // session) can locate the parent pane via `tmux list-panes`. Without
      // this tag, cross-instance parent lookup falls back to undefined and
      // the Exploiter pane gets stacked in the top-level right column
      // instead of being placed next to its SA — see the afterimage 2026-
      // 05-21 run where all five Exploiters were emitted without a
      // `child of …` log line.
      Bun.spawn(
        [
          "tmux",
          "set-option",
          "-p",
          "-t",
          paneId,
          "@omp_session_id",
          sessionId,
        ],
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

    // Sequential: each resize must complete before the next.
    // tmux resize-pane auto-adjusts adjacent panes, so concurrent fire-and-forget
    // requests race and overwrite each other → uneven layout.
    for (let i = 0; i < count - 1; i++) {
      const resizeProc = Bun.spawn(
        ["tmux", "resize-pane", "-t", rightColumnPaneIds[i], "-y", String(targetHeight)],
        { stdout: "ignore", stderr: "ignore" },
      )
      await resizeProc.exited
    }
  } catch {
    // Non-critical — layout will just be slightly uneven
  }
}

/**
 * Locate a tmux pane tagged with the given session_id via the
 * `@omp_session_id` user-option. Returns the matching pane id, or
 * undefined if no pane carries that tag.
 *
 * `tmux list-panes -a` enumerates every pane across every window in the
 * current server, so this works for the cross-BackgroundManager-instance
 * case (an SA's plugin instance asks for the parent paneId that the
 * Orchestrator's plugin instance created).
 */
export async function findPaneBySession(
  sessionId: string,
): Promise<string | undefined> {
  if (!isInsideTmux()) return undefined
  try {
    const proc = Bun.spawn(
      [
        "tmux",
        "list-panes",
        "-a",
        "-F",
        "#{pane_id} #{@omp_session_id}",
      ],
      { stdout: "pipe", stderr: "ignore" },
    )
    const text = await new Response(proc.stdout).text()
    await proc.exited
    for (const line of text.split("\n")) {
      const sep = line.indexOf(" ")
      if (sep < 0) continue
      const candidate = line.slice(sep + 1).trim()
      if (candidate === sessionId) return line.slice(0, sep).trim() || undefined
    }
  } catch {
    // tmux command failed — caller treats undefined as "no parent"
  }
  return undefined
}

/**
 * Close a tmux pane by ID, then rebalance the top-level right column if
 * the pane we just killed was part of it. tmux's default behaviour after
 * `kill-pane` is to give the freed space to one neighbour, which leaves
 * the remaining panes uneven (e.g. 3-up → one 66% / one 33%). We restore
 * the n-등분 layout so the user keeps seeing balanced rows.
 *
 * Child panes (Exploiter split off an SA pane) are NOT in
 * `rightColumnPaneIds` — when they close, tmux's default re-absorb gives
 * all the freed width back to the parent (SA) pane, which is what we
 * want anyway.
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
  const idx = rightColumnPaneIds.indexOf(paneId)
  if (idx >= 0) {
    rightColumnPaneIds.splice(idx, 1)
    if (lastRightPaneId === paneId) {
      lastRightPaneId = rightColumnPaneIds[rightColumnPaneIds.length - 1]
    }
    await rebalanceRightColumn()
  }
}
