import { describe, expect, test } from "bun:test"
import { ConcurrencyManager } from "./concurrency"

describe("ConcurrencyManager", () => {
  test("acquire succeeds immediately under limit", async () => {
    const cm = new ConcurrencyManager({ defaultLimit: 3 })
    await cm.acquire("model-a")
    await cm.acquire("model-a")
    await cm.acquire("model-a")
    expect(cm.getCount("model-a")).toBe(3)
  })

  test("acquire queues at limit", async () => {
    const cm = new ConcurrencyManager({ defaultLimit: 2 })
    await cm.acquire("model-a")
    await cm.acquire("model-a")

    let resolved = false
    const pending = cm.acquire("model-a").then(() => {
      resolved = true
    })

    // Should not resolve immediately
    await new Promise((r) => setTimeout(r, 10))
    expect(resolved).toBe(false)
    expect(cm.getQueueLength("model-a")).toBe(1)

    // Release one — should unblock the waiter
    cm.release("model-a")
    await pending
    expect(resolved).toBe(true)
    expect(cm.getCount("model-a")).toBe(2)
  })

  test("release decrements count when no waiters", () => {
    const cm = new ConcurrencyManager({ defaultLimit: 5 })
    // Manually set up state by acquiring synchronously (under limit)
    cm.acquire("k")
    cm.acquire("k")
    expect(cm.getCount("k")).toBe(2)

    cm.release("k")
    expect(cm.getCount("k")).toBe(1)

    cm.release("k")
    expect(cm.getCount("k")).toBe(0)
  })

  test("per-model limits override default", async () => {
    const cm = new ConcurrencyManager({
      defaultLimit: 10,
      modelLimits: { "openai/gpt-5.4": 1 },
    })
    expect(cm.getLimit("openai/gpt-5.4")).toBe(1)
    expect(cm.getLimit("other/model")).toBe(10)
  })

  test("limit 0 means unlimited", () => {
    const cm = new ConcurrencyManager({ defaultLimit: 0 })
    expect(cm.getLimit("any")).toBe(Infinity)
  })

  test("cancelWaiters rejects queued promises", async () => {
    const cm = new ConcurrencyManager({ defaultLimit: 1 })
    await cm.acquire("k")

    let rejected = false
    cm.acquire("k").catch(() => {
      rejected = true
    })

    cm.cancelWaiters("k")
    await new Promise((r) => setTimeout(r, 10))
    expect(rejected).toBe(true)
    expect(cm.getQueueLength("k")).toBe(0)
  })

  test("clear resets all state", async () => {
    const cm = new ConcurrencyManager({ defaultLimit: 2 })
    await cm.acquire("a")
    await cm.acquire("b")
    cm.clear()
    expect(cm.getCount("a")).toBe(0)
    expect(cm.getCount("b")).toBe(0)
  })

  test("independent keys do not interfere", async () => {
    const cm = new ConcurrencyManager({ defaultLimit: 1 })
    await cm.acquire("model-a")
    await cm.acquire("model-b")
    expect(cm.getCount("model-a")).toBe(1)
    expect(cm.getCount("model-b")).toBe(1)
  })
})
