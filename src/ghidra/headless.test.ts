/**
 * Unit tests for the Ghidra headless launcher module.
 *
 * All tests use an injected {@link SpawnFn} so no real Ghidra installation is
 * required. The `mkdirSync` call inside `runHeadlessImport` is exercised
 * against a real (tmp) path; the test picks a path that already exists
 * ("/tmp") to avoid leaving artefacts behind.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test"
import { GhidraBridgeError } from "./errors.js"
import {
  buildHeadlessMcpConfig,
  resolveGhidraHome,
  resolveProjectPath,
  runHeadlessImport,
  type SpawnFn,
  type SpawnResult,
} from "./headless.js"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSpawn(exitCode: number, stderr = ""): SpawnFn {
  return (_cmd, _args, _opts) => ({
    exitCode,
    stdout: Buffer.alloc(0),
    stderr: Buffer.from(stderr, "utf-8"),
  })
}

function makeThrowingSpawn(code: string): SpawnFn {
  return (_cmd, _args, _opts) => {
    const err = new Error(`spawn error ${code}`) as NodeJS.ErrnoException
    err.code = code
    throw err
  }
}

// ---------------------------------------------------------------------------
// resolveGhidraHome
// ---------------------------------------------------------------------------

describe("resolveGhidraHome", () => {
  let savedEnv: string | undefined

  beforeEach(() => {
    savedEnv = process.env.GHIDRA_HOME
    delete process.env.GHIDRA_HOME
  })

  afterEach(() => {
    if (savedEnv !== undefined) {
      process.env.GHIDRA_HOME = savedEnv
    } else {
      delete process.env.GHIDRA_HOME
    }
  })

  it("reads from config", () => {
    const result = resolveGhidraHome({ ghidraHome: "/opt/ghidra_10" })
    expect(result).toBe("/opt/ghidra_10")
  })

  it("reads from env", () => {
    process.env.GHIDRA_HOME = "/opt/ghidra_env"
    const result = resolveGhidraHome()
    expect(result).toBe("/opt/ghidra_env")
  })

  it("throws when not configured", () => {
    expect(() => resolveGhidraHome()).toThrow(GhidraBridgeError)
    try {
      resolveGhidraHome()
    } catch (err) {
      expect(err).toBeInstanceOf(GhidraBridgeError)
      expect((err as GhidraBridgeError).kind).toBe("not-configured")
    }
  })
})

// ---------------------------------------------------------------------------
// resolveProjectPath
// ---------------------------------------------------------------------------

describe("resolveProjectPath", () => {
  let savedEnv: string | undefined

  beforeEach(() => {
    savedEnv = process.env.OMP_GHIDRA_PROJECT_PATH
    delete process.env.OMP_GHIDRA_PROJECT_PATH
  })

  afterEach(() => {
    if (savedEnv !== undefined) {
      process.env.OMP_GHIDRA_PROJECT_PATH = savedEnv
    } else {
      delete process.env.OMP_GHIDRA_PROJECT_PATH
    }
  })

  it("uses default when no config and no env", () => {
    const result = resolveProjectPath()
    expect(result).toBe("/mnt/D/Hack/omp_ghidra_project")
  })
})

// ---------------------------------------------------------------------------
// runHeadlessImport
// ---------------------------------------------------------------------------

describe("runHeadlessImport", () => {
  let savedGhidraHome: string | undefined

  beforeEach(() => {
    savedGhidraHome = process.env.GHIDRA_HOME
    delete process.env.GHIDRA_HOME
  })

  afterEach(() => {
    if (savedGhidraHome !== undefined) {
      process.env.GHIDRA_HOME = savedGhidraHome
    } else {
      delete process.env.GHIDRA_HOME
    }
  })

  it("calls analyzeHeadless with correct args", () => {
    const capturedArgs: { cmd: string; args: string[] }[] = []
    const fakeSpawn: SpawnFn = (cmd, args, _opts) => {
      capturedArgs.push({ cmd, args })
      return { exitCode: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }
    }

    const binaryPath = "/tmp/chall"
    runHeadlessImport(binaryPath, {
      ghidraHome: "/opt/ghidra",
      projectPath: "/tmp",
      spawn: fakeSpawn,
    })

    expect(capturedArgs).toHaveLength(1)
    const { cmd, args } = capturedArgs[0]!
    expect(cmd).toContain("analyzeHeadless")
    expect(args).toContain("-import")
    expect(args).toContain(binaryPath)
  })

  it("throws GhidraBridgeError not-configured on ENOENT", () => {
    expect(() =>
      runHeadlessImport("/tmp/chall", {
        ghidraHome: "/opt/ghidra",
        projectPath: "/tmp",
        spawn: makeThrowingSpawn("ENOENT"),
      }),
    ).toThrow(GhidraBridgeError)

    try {
      runHeadlessImport("/tmp/chall", {
        ghidraHome: "/opt/ghidra",
        projectPath: "/tmp",
        spawn: makeThrowingSpawn("ENOENT"),
      })
    } catch (err) {
      expect(err).toBeInstanceOf(GhidraBridgeError)
      expect((err as GhidraBridgeError).kind).toBe("not-configured")
    }
  })

  it("throws GhidraBridgeError server-error on non-zero exit", () => {
    expect(() =>
      runHeadlessImport("/tmp/chall", {
        ghidraHome: "/opt/ghidra",
        projectPath: "/tmp",
        spawn: makeSpawn(1, "analysis failed"),
      }),
    ).toThrow(GhidraBridgeError)

    try {
      runHeadlessImport("/tmp/chall", {
        ghidraHome: "/opt/ghidra",
        projectPath: "/tmp",
        spawn: makeSpawn(1, "analysis failed"),
      })
    } catch (err) {
      expect(err).toBeInstanceOf(GhidraBridgeError)
      expect((err as GhidraBridgeError).kind).toBe("server-error")
    }
  })
})

// ---------------------------------------------------------------------------
// buildHeadlessMcpConfig
// ---------------------------------------------------------------------------

describe("buildHeadlessMcpConfig", () => {
  it("returns stdio config", () => {
    const config = buildHeadlessMcpConfig()
    expect(config.type).toBe("stdio")
    expect(config.command).toBe("python3")
    expect(config.args![0]).toContain("bridge_mcp_ghidra.py")
  })
})
