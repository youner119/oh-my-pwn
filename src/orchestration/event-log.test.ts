import { describe, expect, test } from "bun:test"

import {
  EVENT_SCHEMA_VERSION,
  foldEvents,
  foldSubmissions,
  orchestratorTaskId,
  type Event,
} from "./event-log"

/** Stamp the common EventCommon fields onto a type-specific payload. */
function ev(partial: Omit<Event, "version" | "ts" | "instance_id">, ts = "2026-07-10T00:00:00.000Z"): Event {
  return {
    version: EVENT_SCHEMA_VERSION,
    ts,
    instance_id: "test-instance",
    ...partial,
  } as Event
}

describe("foldEvents (T34 session_id keying)", () => {
  test("task_started registers a running node with task_id preserved", () => {
    const tree = foldEvents([
      ev({
        type: "task_started",
        session_id: "ses_child",
        task_id: "omp-task-1",
        parent_session_id: "ses_parent",
        agent: "vulnhunter",
        description: "VH-1",
      }),
    ])
    expect(tree.nodes).toHaveLength(1)
    const node = tree.nodes[0]
    // task_id is the parent handle, kept for display; keying was by session_id.
    expect(node.task_id).toBe("omp-task-1")
    expect(node.session_id).toBe("ses_child")
    expect(node.role).toBe("vulnhunter")
    expect(node.status).toBe("running")
  })

  test("task_created is no longer emitted — a bare queued event does not exist", () => {
    // Only task_started onwards; queued is not logged (T34).
    const tree = foldEvents([])
    expect(tree.nodes).toHaveLength(0)
  })

  test("task_terminated marks the node terminated with ended_at", () => {
    const tree = foldEvents([
      ev({
        type: "task_started",
        session_id: "ses_x",
        task_id: "t1",
        parent_session_id: "ses_p",
        agent: "exploiter",
        description: "exp",
      }),
      ev({ type: "task_terminated", session_id: "ses_x" }, "2026-07-10T00:01:00.000Z"),
    ])
    expect(tree.nodes[0].status).toBe("terminated")
    expect(tree.nodes[0].ended_at).toBe("2026-07-10T00:01:00.000Z")
  })

  test("failed / cancelled / completed key on session_id", () => {
    const start = (sid: string, tid: string): Event =>
      ev({
        type: "task_started",
        session_id: sid,
        task_id: tid,
        parent_session_id: "ses_p",
        agent: "strategist",
        description: "SA",
      })
    const tree = foldEvents([
      start("ses_a", "ta"),
      start("ses_b", "tb"),
      start("ses_c", "tc"),
      ev({ type: "task_failed", session_id: "ses_a", error: "boom" }),
      ev({ type: "task_cancelled", session_id: "ses_b" }),
      ev({ type: "task_completed", session_id: "ses_c", via: "idle" }),
    ])
    const byId = new Map(tree.nodes.map((n) => [n.task_id, n.status]))
    expect(byId.get("ta")).toBe("failed")
    expect(byId.get("tb")).toBe("cancelled")
    expect(byId.get("tc")).toBe("completed")
  })

  test("child parent_task_id resolves to orchestrator sentinel", () => {
    const tree = foldEvents([
      ev({
        type: "orchestrator_registered",
        session_id: "ses_orch",
        agent: "orchestrator",
        challenge_name: "chal",
      }),
      ev({
        type: "task_started",
        session_id: "ses_child",
        task_id: "t1",
        parent_session_id: "ses_orch",
        agent: "vulnhunter",
        description: "VH",
      }),
    ])
    const child = tree.nodes.find((n) => n.task_id === "t1")!
    expect(child.parent_task_id).toBe(orchestratorTaskId("ses_orch"))
  })

  test("task_submitted / task_consumed do not change tree status (ledger-only)", () => {
    const tree = foldEvents([
      ev({
        type: "task_started",
        session_id: "ses_x",
        task_id: "t1",
        parent_session_id: "ses_p",
        agent: "exploiter",
        description: "exp",
      }),
      ev({ type: "task_submitted", session_id: "ses_x", cycle: 1, result_path: "/tmp/x-1.json" }),
      ev({ type: "task_consumed", session_id: "ses_x", cycle: 1 }),
    ])
    // Still running — submit/consume are for the manager ledger, not the tree.
    expect(tree.nodes[0].status).toBe("running")
  })
})

describe("foldSubmissions (T34 submission ledger)", () => {
  test("empty when no submission events", () => {
    expect(foldSubmissions([]).size).toBe(0)
  })

  test("counts submits and consumes per session", () => {
    const ledgers = foldSubmissions([
      ev({ type: "task_submitted", session_id: "ses_x", cycle: 1, result_path: "/x-1.json" }),
      ev({ type: "task_submitted", session_id: "ses_x", cycle: 2, result_path: "/x-2.json" }),
      ev({ type: "task_consumed", session_id: "ses_x", cycle: 1 }),
    ])
    const l = ledgers.get("ses_x")!
    expect(l.submissions).toHaveLength(2)
    expect(l.consumedCount).toBe(1)
    // Unconsumed exists (2 > 1); next unconsumed = submissions[consumedCount].
    expect(l.submissions.length > l.consumedCount).toBe(true)
    expect(l.submissions[l.consumedCount].result_path).toBe("/x-2.json")
  })

  test("fully consumed → no unconsumed", () => {
    const ledgers = foldSubmissions([
      ev({ type: "task_submitted", session_id: "ses_x", cycle: 1, result_path: "/x-1.json" }),
      ev({ type: "task_consumed", session_id: "ses_x", cycle: 1 }),
    ])
    const l = ledgers.get("ses_x")!
    expect(l.submissions.length > l.consumedCount).toBe(false)
  })

  test("submissions sorted by cycle regardless of event order", () => {
    const ledgers = foldSubmissions([
      ev({ type: "task_submitted", session_id: "ses_x", cycle: 2, result_path: "/x-2.json" }),
      ev({ type: "task_submitted", session_id: "ses_x", cycle: 1, result_path: "/x-1.json" }),
    ])
    const l = ledgers.get("ses_x")!
    expect(l.submissions.map((s) => s.cycle)).toEqual([1, 2])
    expect(l.submissions[0].result_path).toBe("/x-1.json")
  })

  test("isolates ledgers per session", () => {
    const ledgers = foldSubmissions([
      ev({ type: "task_submitted", session_id: "ses_a", cycle: 1, result_path: "/a-1.json" }),
      ev({ type: "task_submitted", session_id: "ses_b", cycle: 1, result_path: "/b-1.json" }),
      ev({ type: "task_consumed", session_id: "ses_a", cycle: 1 }),
    ])
    expect(ledgers.get("ses_a")!.consumedCount).toBe(1)
    expect(ledgers.get("ses_b")!.consumedCount).toBe(0)
  })
})
