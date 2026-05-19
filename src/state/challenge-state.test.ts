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
    expect(parsed.parallel_config?.max_cycles).toBe(20)
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

  /* ── omp-setup agent — T01 schema additions ────────────────────────── */

  test("accepts setup-gate fields (challenge_type, setup_complete, setup_unsupported_reason)", () => {
    const state = {
      ...createInitialChallengeState(baseInput),
      challenge_type: "user-mode-elf",
      setup_complete: true,
      setup_unsupported_reason: null,
    }
    const parsed = ChallengeStateSchema.parse(state)
    expect(parsed.challenge_type).toBe("user-mode-elf")
    expect(parsed.setup_complete).toBe(true)
    expect(parsed.setup_unsupported_reason).toBeNull()
  })

  test("accepts unsupported challenge_type with diagnostic reason", () => {
    const state = {
      ...createInitialChallengeState(baseInput),
      challenge_type: "unsupported",
      setup_complete: false,
      setup_unsupported_reason:
        "kernel challenge detected: vmlinux + qemu-system in run.sh",
    }
    const parsed = ChallengeStateSchema.parse(state)
    expect(parsed.challenge_type).toBe("unsupported")
    expect(parsed.setup_complete).toBe(false)
    expect(parsed.setup_unsupported_reason).toContain("kernel")
  })

  test("rejects challenge_type values outside the current enum", () => {
    // Future types (kernel, library-only, browser, …) are reserved but
    // not yet in the enum — parser must refuse them so callers can't
    // silently emit unrecognised values.
    for (const value of [
      "kernel",
      "library-only",
      "multi-binary",
      "source-only",
      "browser",
      "interpreter",
      "unknown",
      "",
    ]) {
      const bad = {
        ...createInitialChallengeState(baseInput),
        challenge_type: value,
      }
      expect(() => ChallengeStateSchema.parse(bad)).toThrow()
    }
  })

  test("accepts challenge_summary (facts-only per D10)", () => {
    const state = {
      ...createInitialChallengeState(baseInput),
      challenge_type: "user-mode-elf",
      challenge_summary:
        "Ubuntu 24.04 / glibc 2.39 user-mode x86_64 ELF. NEEDED: libc/libm/libz/libbz2/liblzma. " +
        "Mitigations: NX=on PIE=on Canary=on RELRO=full seccomp=false. Remote via xinetd on TCP/10039.",
    }
    const parsed = ChallengeStateSchema.parse(state)
    expect(parsed.challenge_summary).toContain("Ubuntu 24.04")
    expect(parsed.challenge_summary).toContain("Canary=on")
    // Schema does not enforce D10 — that is a prompt-level rule for the
    // setup agent. Schema only enforces "optional string".
  })

  test("challenge_summary is optional (pre-omp-setup state)", () => {
    const stateWithout = createInitialChallengeState(baseInput)
    expect(stateWithout.challenge_summary).toBeUndefined()
  })

  test("createInitialChallengeState seeds workspace_root when supplied (T01.6)", () => {
    const state = createInitialChallengeState({
      ...baseInput,
      workspace_root: "/abs/plugin-root/workspace",
    })
    expect(state.workspace_root).toBe("/abs/plugin-root/workspace")
  })

  test("workspace_root is optional (test / standalone path)", () => {
    const stateWithout = createInitialChallengeState(baseInput)
    expect(stateWithout.workspace_root).toBeUndefined()
  })

  test("challenge_summary accepts the unsupported-case shape (kernel example)", () => {
    const state = {
      ...createInitialChallengeState(baseInput),
      challenge_type: "unsupported",
      setup_unsupported_reason:
        "kernel challenge detected: vmlinux + qemu-system in run.sh",
      challenge_summary:
        "Linux kernel exploitation challenge. bzImage (5.4MB self-extracting kernel image) + " +
        "rootfs.cpio.gz (4.9MB cpio initramfs) + qemu-system-x86_64 boot with KASLR/SMAP/SMEP/PTI. " +
        "Remote: socat TCP-LISTEN:8080.",
    }
    const parsed = ChallengeStateSchema.parse(state)
    expect(parsed.challenge_summary).toContain("kernel")
    expect(parsed.challenge_summary).toContain("KASLR")
    expect(parsed.setup_unsupported_reason).toContain("kernel challenge")
  })

  test("setup_unsupported_reason accepts null, string, and undefined", () => {
    const variants = [
      { setup_unsupported_reason: null },
      { setup_unsupported_reason: "host verify failed: missing libz.so.1" },
      {}, // undefined
    ]
    for (const partial of variants) {
      const state = { ...createInitialChallengeState(baseInput), ...partial }
      expect(() => ChallengeStateSchema.parse(state)).not.toThrow()
    }
  })

  test("accepts binary_input_path and binary_input_sha256 (input identity contract)", () => {
    const state = {
      ...createInitialChallengeState(baseInput),
      binary_input_path: "/c/deploy/prob",
      binary_input_sha256:
        "b3ae5f5113462273249bfb295cd2eb5027f98a5ad50a33876935b435b2a9a9ca",
      binary_path: "/c/.omp/artifacts/prob",
      binary_sha256: "patched-sha-here",
    }
    const parsed = ChallengeStateSchema.parse(state)
    expect(parsed.binary_input_path).toBe("/c/deploy/prob")
    expect(parsed.binary_input_sha256).toBe(
      "b3ae5f5113462273249bfb295cd2eb5027f98a5ad50a33876935b435b2a9a9ca",
    )
    expect(parsed.binary_path).toBe("/c/.omp/artifacts/prob")
    expect(parsed.binary_sha256).toBe("patched-sha-here")
  })

  test("rejects empty binary_input_path string (min(1) enforced)", () => {
    const bad = {
      ...createInitialChallengeState(baseInput),
      binary_input_path: "",
    }
    expect(() => ChallengeStateSchema.parse(bad)).toThrow()
  })

  test("accepts extracted_libs as empty map (static binary)", () => {
    const state = {
      ...createInitialChallengeState(baseInput),
      libc_version: "static",
      extracted_libs: {},
    }
    const parsed = ChallengeStateSchema.parse(state)
    expect(parsed.libc_version).toBe("static")
    expect(parsed.extracted_libs).toEqual({})
  })

  test("accepts extracted_libs with multi-NEEDED entries (afterimage-style)", () => {
    const state = {
      ...createInitialChallengeState(baseInput),
      libc_version: "2.39",
      extracted_libs: {
        "libc.so.6": "/c/.omp/artifacts/libc.so.6",
        "libm.so.6": "/c/.omp/artifacts/libm.so.6",
        "libz.so.1": "/c/.omp/artifacts/libz.so.1",
        "libbz2.so.1.0": "/c/.omp/artifacts/libbz2.so.1.0",
        "liblzma.so.5": "/c/.omp/artifacts/liblzma.so.5",
        "ld-linux-x86-64.so.2": "/c/.omp/artifacts/ld-linux-x86-64.so.2",
      },
      libc_path: "/c/.omp/artifacts/libc.so.6",
      ld_path: "/c/.omp/artifacts/ld-linux-x86-64.so.2",
    }
    const parsed = ChallengeStateSchema.parse(state)
    expect(Object.keys(parsed.extracted_libs ?? {})).toHaveLength(6)
    expect(parsed.extracted_libs?.["libz.so.1"]).toBe(
      "/c/.omp/artifacts/libz.so.1",
    )
    // Alias parity: libc_path / ld_path are the same string as the
    // matching extracted_libs entry. Setup agent must keep them in sync.
    expect(parsed.libc_path).toBe(parsed.extracted_libs?.["libc.so.6"])
    expect(parsed.ld_path).toBe(parsed.extracted_libs?.["ld-linux-x86-64.so.2"])
  })

  test("rejects extracted_libs with non-string values", () => {
    const bad = {
      ...createInitialChallengeState(baseInput),
      extracted_libs: { "libc.so.6": 42 },
    }
    expect(() => ChallengeStateSchema.parse(bad)).toThrow()
  })

  test("legacy state with deprecated patchelf-backup fields still parses", () => {
    // omp-setup agent retired in-place patchelf, but historical state.json
    // files written by `omp_run_envsetup` contain `binary_patched`,
    // `binary_original_path`, `binary_original_sha256`. Schema retains
    // these as @deprecated so old state remains readable.
    const legacyState = {
      schema_version: "1",
      challenge_dir: "/c",
      binary_path: "/c/deploy/prob",
      dockerfile_path: "/c/Dockerfile",
      binary_patched: true,
      binary_original_path: "/c/.omp/artifacts/prob.orig",
      binary_original_sha256: "legacy-sha-256",
      created_at: "2026-04-10T00:00:00.000Z",
      updated_at: "2026-04-10T00:00:00.000Z",
    }
    const parsed = ChallengeStateSchema.parse(legacyState)
    expect(parsed.binary_patched).toBe(true)
    expect(parsed.binary_original_path).toBe("/c/.omp/artifacts/prob.orig")
    expect(parsed.binary_original_sha256).toBe("legacy-sha-256")
  })

  test("backward compat: pre-omp-setup state (no setup-gate / extracted_libs / binary_input) still parses", () => {
    const oldState = {
      schema_version: "1",
      challenge_dir: "/c",
      binary_path: "/c/bin",
      dockerfile_path: "/c/Dockerfile",
      created_at: "2026-04-10T00:00:00.000Z",
      updated_at: "2026-04-10T00:00:00.000Z",
    }
    const parsed = ChallengeStateSchema.parse(oldState)
    expect(parsed.challenge_type).toBeUndefined()
    expect(parsed.setup_complete).toBeUndefined()
    expect(parsed.setup_unsupported_reason).toBeUndefined()
    expect(parsed.challenge_summary).toBeUndefined()
    expect(parsed.binary_input_path).toBeUndefined()
    expect(parsed.binary_input_sha256).toBeUndefined()
    expect(parsed.extracted_libs).toBeUndefined()
  })
})
