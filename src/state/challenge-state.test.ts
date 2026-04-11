import { describe, expect, test } from "bun:test"
import {
  ChallengeStateSchema,
  createInitialChallengeState,
} from "./challenge-state"
import { CHALLENGE_STATE_SCHEMA_VERSION } from "./constants"

const baseInput = {
  challenge_dir: "/tmp/challenge-x",
  binary_path: "/tmp/challenge-x/chall",
  dockerfile_path: "/tmp/challenge-x/Dockerfile",
}

describe("ChallengeStateSchema", () => {
  test("createInitialChallengeState seeds a valid minimal state", () => {
    const now = new Date("2026-04-10T00:00:00.000Z")
    const state = createInitialChallengeState(baseInput, now)

    expect(state.schema_version).toBe(CHALLENGE_STATE_SCHEMA_VERSION)
    expect(state.challenge_dir).toBe(baseInput.challenge_dir)
    expect(state.binary_path).toBe(baseInput.binary_path)
    expect(state.dockerfile_path).toBe(baseInput.dockerfile_path)
    expect(state.source_present).toBe(false)
    expect(state.source_paths).toEqual([])
    expect(state.vuln_candidates).toEqual([])
    expect(state.stages).toEqual([])
    expect(state.leaks).toEqual([])
    expect(state.corrections).toEqual([])
    expect(state.created_at).toBe("2026-04-10T00:00:00.000Z")
    expect(state.updated_at).toBe("2026-04-10T00:00:00.000Z")
  })

  test("parses a fully populated state round-trip", () => {
    const fullState = {
      schema_version: "1",
      challenge_dir: "/c",
      binary_path: "/c/bin",
      dockerfile_path: "/c/Dockerfile",
      binary_sha256: "deadbeef",
      source_present: true,
      source_paths: ["/c/chal.c"],
      libc_version: "2.35",
      libc_path: "/c/.omp/artifacts/libc.so.6",
      ld_path: "/c/.omp/artifacts/ld-linux-x86-64.so.2",
      docker_image: "sha256:abc",
      mitigations: {
        nx: true,
        pie: true,
        canary: true,
        relro: "full",
        seccomp: false,
      },
      remote: { host: "127.0.0.1", port: 1337, wrapper: "ynetd" },
      reverser_summary_path: "/c/.omp/artifacts/reverse.md",
      vuln_candidates: [
        {
          id: "v1",
          primitive: "stack_bof",
          location: "main+0x40",
          confidence: 0.8,
          rationale: "unchecked read",
        },
      ],
      stages: [
        {
          id: "leak-libc",
          description: "obtain libc base",
          status: "passed",
          attempts: ["/c/.omp/exploit/leak.py"],
          started_at: "2026-04-10T00:00:00.000Z",
          finished_at: "2026-04-10T00:01:00.000Z",
        },
      ],
      current_stage_index: 0,
      current_exploit_script: "/c/.omp/exploit/current.py",
      leaks: [
        {
          name: "libc_base",
          value: "0x7ffff7a00000",
          stage: "leak-libc",
          discovered_at: "2026-04-10T00:01:00.000Z",
        },
      ],
      corrections: [
        {
          timestamp: "2026-04-10T00:02:00.000Z",
          user_text: "libc는 2.35야",
          applied_delta: "libc_version 2.31 → 2.35",
        },
      ],
      created_at: "2026-04-10T00:00:00.000Z",
      updated_at: "2026-04-10T00:02:00.000Z",
    }

    const parsed = ChallengeStateSchema.parse(fullState)
    expect(parsed.libc_version).toBe("2.35")
    expect(parsed.stages[0]?.status).toBe("passed")
    expect(parsed.leaks[0]?.name).toBe("libc_base")
    expect(parsed.corrections[0]?.user_text).toBe("libc는 2.35야")
  })

  test("rejects a state missing required identity fields", () => {
    const bad = { schema_version: "1" }
    expect(() => ChallengeStateSchema.parse(bad)).toThrow()
  })

  test("rejects an invalid stage status", () => {
    const bad = {
      ...createInitialChallengeState(baseInput),
      stages: [{ id: "s1", status: "bogus", attempts: [] }],
    }
    expect(() => ChallengeStateSchema.parse(bad)).toThrow()
  })

  test("rejects a malformed ISO-8601 timestamp", () => {
    const bad = {
      ...createInitialChallengeState(baseInput),
      created_at: "yesterday",
    }
    expect(() => ChallengeStateSchema.parse(bad)).toThrow()
  })

  test("accepts ISO timestamps with and without fractional seconds", () => {
    const withFraction = {
      ...createInitialChallengeState(baseInput),
      created_at: "2026-04-10T00:00:00.123Z",
      updated_at: "2026-04-10T00:00:00.123456Z",
    }
    expect(() => ChallengeStateSchema.parse(withFraction)).not.toThrow()

    const withoutFraction = {
      ...createInitialChallengeState(baseInput),
      created_at: "2026-04-10T00:00:00Z",
      updated_at: "2026-04-10T00:00:00+09:00",
    }
    expect(() => ChallengeStateSchema.parse(withoutFraction)).not.toThrow()
  })

  test("rejects a user correction with a non-ISO timestamp", () => {
    const bad = {
      ...createInitialChallengeState(baseInput),
      corrections: [
        { timestamp: "last tuesday", user_text: "fix it" },
      ],
    }
    expect(() => ChallengeStateSchema.parse(bad)).toThrow()
  })
})
