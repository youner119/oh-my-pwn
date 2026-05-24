import { describe, expect, test } from "bun:test"
import {
  ChallengeStateSchema,
  createInitialChallengeState,
} from "./challenge-state"
import { CHALLENGE_STATE_SCHEMA_VERSION } from "./constants"

const baseInput = {
  challenge_dir: "/tmp/challenge-x",
}

describe("ChallengeStateSchema", () => {
  test("createInitialChallengeState seeds only challenge_dir + meta (contract-load-detect-split D1)", () => {
    const now = new Date("2026-04-10T00:00:00.000Z")
    const state = createInitialChallengeState(baseInput, now)

    expect(state.schema_version).toBe(CHALLENGE_STATE_SCHEMA_VERSION)
    expect(state.challenge_dir).toBe(baseInput.challenge_dir)
    // Loader no longer seeds binary / dockerfile / source — those are written
    // by omp-setup Phase 0 (Detect) via omp_patch_state.
    expect(state.binary_input_path).toBeUndefined()
    expect(state.binary_input_sha256).toBeUndefined()
    expect(state.dockerfile_path).toBeUndefined()
    expect(state.binary_path).toBeUndefined()
    expect(state.binary_sha256).toBeUndefined()
    expect(state.source_present).toBe(false)
    expect(state.source_paths).toEqual([])
    expect(state.vuln_candidates).toEqual([])
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
          verification_result: "confirmed",
          agent: "VH-3",
          description: "main 의 unchecked read — saved RIP 위 stack BOF",
          gives_count: 1,
          needs_count: 0,
          has_poc: true,
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
    expect(parsed.vuln_candidates[0]?.verification_result).toBe("confirmed")
    expect(parsed.vuln_candidates[0]?.has_poc).toBe(true)
    expect(parsed.vuln_candidates[0]?.description).toContain("BOF")
    expect(parsed.corrections[0]?.user_text).toBe("libc는 2.35야")
  })

  test("rejects a state missing required identity fields", () => {
    const bad = { schema_version: "1" }
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

  // Detail-field tests (origin_type / derived_from / poc_script_path / gives /
  // needs / combined_from / verification_blockers) — moved to per-file detail
  // io / tool tests in P2-P3. Spec: state-split-vuln-candidates.md D2/D6.
  // state.json 의 vuln_candidates 영역은 summary 만 박힘.

  test("accepts parallel_config with defaults", () => {
    const state = {
      ...createInitialChallengeState(baseInput),
      parallel_config: {},
    }
    const parsed = ChallengeStateSchema.parse(state)
    expect(parsed.parallel_config?.vh_instance_count).toBe(10)
    expect(parsed.parallel_config?.sa_instance_count).toBe(10)
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

  test("etc accepts free-form Record<string, unknown> (D7 kernel example)", () => {
    const state = {
      ...createInitialChallengeState(baseInput),
      challenge_type: "unsupported" as const,
      unsupported_kind: "kernel-pwn" as const,
      setup_unsupported_reason: "kernel challenge",
      challenge_summary: "kernel summary",
      setup_complete: true,
      etc: {
        kernel_vmlinux_path: "/c/vmlinux",
        kernel_bzimage_path: "/c/bzImage",
        kernel_initramfs_path: "/c/rootfs.cpio.gz",
        kernel_qemu_cmd: "qemu-system-x86_64 -kernel bzImage ...",
        kernel_kaslr: true,
        kernel_smap: true,
        kernel_smep: true,
        kernel_pti: false,
        kernel_modules: ["a.ko", "b.ko"],
      },
    }
    const parsed = ChallengeStateSchema.parse(state)
    expect(parsed.etc?.kernel_vmlinux_path).toBe("/c/vmlinux")
    expect(parsed.etc?.kernel_kaslr).toBe(true)
    expect(parsed.etc?.kernel_modules).toEqual(["a.ko", "b.ko"])
  })

  test("etc is optional and defaults to undefined", () => {
    const stateWithout = createInitialChallengeState(baseInput)
    expect(stateWithout.etc).toBeUndefined()
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

  test("legacy state with retired patchelf-backup fields is silently stripped", () => {
    // Historical state.json files written by the legacy `omp_run_envsetup`
    // (pre-T19) carry `binary_patched`, `binary_original_path`,
    // `binary_original_sha256`. Those fields were removed from the schema
    // — Zod's default strip mode silently drops them on parse, so old
    // state files still load (the unknown keys do not throw).
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
    const parsed = ChallengeStateSchema.parse(legacyState) as Record<
      string,
      unknown
    >
    expect(parsed["binary_patched"]).toBeUndefined()
    expect(parsed["binary_original_path"]).toBeUndefined()
    expect(parsed["binary_original_sha256"]).toBeUndefined()
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
