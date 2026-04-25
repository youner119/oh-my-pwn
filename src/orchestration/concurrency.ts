/**
 * ConcurrencyManager — limits simultaneous tasks per model endpoint.
 *
 * Ported from OmO's concurrency.ts, simplified:
 * - No provider-level fallback (only model-level + default)
 * - Same acquire/release/queue pattern
 */

import type { ConcurrencyConfig } from "./types"
import { DEFAULT_CONCURRENCY_CONFIG } from "./types"

interface QueueEntry {
  resolve: () => void
  reject: (error: Error) => void
}

export class ConcurrencyManager {
  private readonly config: ConcurrencyConfig
  private readonly counts = new Map<string, number>()
  private readonly queues = new Map<string, QueueEntry[]>()

  constructor(config?: Partial<ConcurrencyConfig>) {
    this.config = { ...DEFAULT_CONCURRENCY_CONFIG, ...config }
  }

  /** Effective concurrency limit for a given model key. */
  getLimit(key: string): number {
    const modelLimit = this.config.modelLimits?.[key]
    if (modelLimit !== undefined) return modelLimit === 0 ? Infinity : modelLimit
    return this.config.defaultLimit === 0 ? Infinity : this.config.defaultLimit
  }

  /**
   * Acquire a concurrency slot. Resolves immediately if under limit,
   * otherwise queues until a slot is released.
   */
  async acquire(key: string): Promise<void> {
    const limit = this.getLimit(key)
    const current = this.counts.get(key) ?? 0

    if (current < limit) {
      this.counts.set(key, current + 1)
      return
    }

    // At limit — queue and wait
    return new Promise<void>((resolve, reject) => {
      const queue = this.queues.get(key) ?? []
      queue.push({ resolve, reject })
      this.queues.set(key, queue)
    })
  }

  /** Release a concurrency slot, unblocking the next queued waiter if any. */
  release(key: string): void {
    const queue = this.queues.get(key)
    if (queue && queue.length > 0) {
      // Hand off to next waiter (count stays the same)
      const next = queue.shift()!
      next.resolve()
      if (queue.length === 0) this.queues.delete(key)
    } else {
      // No waiters — decrement count
      const current = this.counts.get(key) ?? 1
      if (current <= 1) {
        this.counts.delete(key)
      } else {
        this.counts.set(key, current - 1)
      }
    }
  }

  /** Cancel all queued waiters for a key. */
  cancelWaiters(key: string): void {
    const queue = this.queues.get(key)
    if (!queue) return
    for (const entry of queue) {
      entry.reject(new Error(`Concurrency waiters cancelled for key: ${key}`))
    }
    this.queues.delete(key)
  }

  /** Cancel all waiters and reset all state. */
  clear(): void {
    for (const key of this.queues.keys()) {
      this.cancelWaiters(key)
    }
    this.counts.clear()
  }

  /** Current active count for a key. */
  getCount(key: string): number {
    return this.counts.get(key) ?? 0
  }

  /** Current queue length for a key. */
  getQueueLength(key: string): number {
    return this.queues.get(key)?.length ?? 0
  }
}
