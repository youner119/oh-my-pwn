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

  test("accepts vuln_candidates with origin_type and derived_from", () => {
    const state = {
      ...createInitialChallengeState(baseInput),
      vuln_candidates: [
        {
          id: "vuln_bof_main",
          primitive: "stack_bof",
          confidence: 0.9,
          origin_type: "initial",
        },
        {
          id: "vuln_bof_leak",
          primitive: "bof_libc_leak",
          confidence: 0.7,
          origin_type: "derived",
          derived_from: "vuln_bof_main",
        },
        {
          id: "vuln_heap_obs",
          primitive: "heap_uaf",
          confidence: 0.5,
          origin_type: "incidental",
          derived_from: "vuln_bof_main",
        },
      ],
    }
    const parsed = ChallengeStateSchema.parse(state)
    expect(parsed.vuln_candidates).toHaveLength(3)
    expect(parsed.vuln_candidates[0]?.origin_type).toBe("initial")
    expect(parsed.vuln_candidates[1]?.origin_type).toBe("derived")
    expect(parsed.vuln_candidates[1]?.derived_from).toBe("vuln_bof_main")
    expect(parsed.vuln_candidates[2]?.origin_type).toBe("incidental")
  })

  test("accepts vuln_candidates with poc_script_path, gives, needs, combined_from", () => {
    const state = {
      ...createInitialChallengeState(baseInput),
      vuln_candidates: [
        {
          id: "vuln_1",
          primitive: "stack_bof",
          verified: true,
          verification_result: "confirmed",
          poc_script_path: "/c/.omp/exploit/vuln_1/verify.py",
          gives: ["rip_control"],
          needs: ["canary"],
        },
        {
          id: "vuln_2",
          primitive: "fmt_string_leak",
          verified: true,
          verification_result: "confirmed",
          poc_script_path: "/c/.omp/exploit/vuln_2/verify.py",
          gives: ["libc_base", "canary"],
          needs: [],
        },
        {
          id: "vuln_3",
          primitive: "rop_shell",
          verified: true,
          verification_result: "confirmed",
          poc_script_path: "/c/.omp/exploit/vuln_3/exploit.py",
          gives: ["shell"],
          needs: ["rip_control", "libc_base"],
          combined_from: ["vuln_1", "vuln_2"],
          origin_type: "derived",
        },
      ],
    }
    const parsed = ChallengeStateSchema.parse(state)
    expect(parsed.vuln_candidates[0]?.gives).toEqual(["rip_control"])
    expect(parsed.vuln_candidates[0]?.needs).toEqual(["canary"])
    expect(parsed.vuln_candidates[0]?.poc_script_path).toContain("verify.py")
    expect(parsed.vuln_candidates[2]?.combined_from).toEqual(["vuln_1", "vuln_2"])
    expect(parsed.vuln_candidates[2]?.gives).toEqual(["shell"])
  })

  test("rejects invalid origin_type", () => {
    const bad = {
      ...createInitialChallengeState(baseInput),
      vuln_candidates: [
        { id: "v1", primitive: "bof", origin_type: "magic" },
      ],
    }
    expect(() => ChallengeStateSchema.parse(bad)).toThrow()
  })

  test("accepts parallel_config with defaults", () => {
    const state = {
      ...createInitialChallengeState(baseInput),
      parallel_config: {},
    }
    const parsed = ChallengeStateSchema.parse(state)
    expect(parsed.parallel_config?.vh_instance_count).toBe(3)
    expect(parsed.parallel_config?.sa_instance_count).toBe(3)
    expect(parsed.parallel_config?.max_cycles).toBe(5)
    expect(parsed.parallel_config?.max_retries_per_candidate).toBe(3)
  })

  test("accepts parallel_config with user overrides", () => {
    const state = {
      ...createInitialChallengeState(baseInput),
      parallel_config: { vh_instance_count: 5, sa_instance_count: 5 },
    }
    const parsed = ChallengeStateSchema.parse(state)
    expect(parsed.parallel_config?.vh_instance_count).toBe(5)
    expect(parsed.parallel_config?.sa_instance_count).toBe(5)
  })

  test("accepts pipeline phase and termination reason", () => {
    const state = {
      ...createInitialChallengeState(baseInput),
      pipeline_phase: "terminated",
      pipeline_cycle: 2,
      pipeline_termination_reason: "flag_found",
    }
    const parsed = ChallengeStateSchema.parse(state)
    expect(parsed.pipeline_phase).toBe("terminated")
    expect(parsed.pipeline_cycle).toBe(2)
    expect(parsed.pipeline_termination_reason).toBe("flag_found")
  })

  test("rejects invalid pipeline_phase", () => {
    const bad = {
      ...createInitialChallengeState(baseInput),
      pipeline_phase: "running",
    }
    expect(() => ChallengeStateSchema.parse(bad)).toThrow()
  })

  test("rejects invalid termination_reason", () => {
    const bad = {
      ...createInitialChallengeState(baseInput),
      pipeline_termination_reason: "timeout",
    }
    expect(() => ChallengeStateSchema.parse(bad)).toThrow()
  })

  test("backward compat: existing state without parallel fields still parses", () => {
    const oldState = {
      schema_version: "1",
      challenge_dir: "/c",
      binary_path: "/c/bin",
      dockerfile_path: "/c/Dockerfile",
      vuln_candidates: [
        { id: "v1", primitive: "stack_bof", confidence: 0.8 },
      ],
      created_at: "2026-04-10T00:00:00.000Z",
      updated_at: "2026-04-10T00:00:00.000Z",
    }
    const parsed = ChallengeStateSchema.parse(oldState)
    expect(parsed.parallel_config).toBeUndefined()
    expect(parsed.pipeline_phase).toBeUndefined()
    expect(parsed.pipeline_cycle).toBeUndefined()
    expect(parsed.pipeline_termination_reason).toBeUndefined()
    expect(parsed.vuln_candidates[0]?.origin_type).toBeUndefined()
    expect(parsed.vuln_candidates[0]?.derived_from).toBeUndefined()
  })
})
