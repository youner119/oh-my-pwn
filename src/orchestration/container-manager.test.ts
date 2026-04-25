import { describe, expect, test } from "bun:test"
import { PwnoContainerManager } from "./container-manager"
import type { ShellRunner } from "./container-manager"

/** Fake shell runner that simulates Docker commands. */
function createFakeShell(options?: {
  containerRunning?: boolean
}): ShellRunner & { commands: string[][] } {
  const commands: string[][] = []
  let running = options?.containerRunning ?? false

  return {
    commands,
    async run(cmd: string[]) {
      commands.push([...cmd])
      const joined = cmd.join(" ")

      if (joined.includes("docker inspect")) {
        return {
          exitCode: running ? 0 : 1,
          stdout: running ? "true" : "",
          stderr: running ? "" : "No such container",
        }
      }
      if (joined.includes("docker run")) {
        running = true
        return { exitCode: 0, stdout: "container-id-abc", stderr: "" }
      }
      if (joined.includes("docker stop") || joined.includes("docker rm")) {
        running = false
        return { exitCode: 0, stdout: "", stderr: "" }
      }
      return { exitCode: 0, stdout: "", stderr: "" }
    },
  }
}

describe("PwnoContainerManager", () => {
  test("ensure starts container when not running", async () => {
    const shell = createFakeShell({ containerRunning: false })
    const mgr = new PwnoContainerManager(
      { workspacePath: "/test/workspace" },
      shell,
    )

    const status = await mgr.ensure()
    expect(status.running).toBe(true)
    expect(status.url).toBe("http://127.0.0.1:5500/mcp")

    // Should have called docker run
    const runCmd = shell.commands.find((c) => c.includes("run"))
    expect(runCmd).toBeDefined()
    expect(runCmd).toContain("omp-pwno")
  })

  test("ensure skips start when already running", async () => {
    const shell = createFakeShell({ containerRunning: true })
    const mgr = new PwnoContainerManager(undefined, shell)

    const status = await mgr.ensure()
    expect(status.running).toBe(true)

    // Should NOT have called docker run
    const runCmd = shell.commands.find((c) => c.includes("run"))
    expect(runCmd).toBeUndefined()
  })

  test("stop calls docker stop + rm", async () => {
    const shell = createFakeShell({ containerRunning: true })
    const mgr = new PwnoContainerManager(undefined, shell)

    await mgr.stop()

    const stopCmd = shell.commands.find((c) => c.includes("stop"))
    const rmCmd = shell.commands.find((c) =>
      c.includes("rm") && c.includes("-f"),
    )
    expect(stopCmd).toBeDefined()
    expect(rmCmd).toBeDefined()
  })

  test("isRunning returns correct status", async () => {
    const shell = createFakeShell({ containerRunning: true })
    const mgr = new PwnoContainerManager(undefined, shell)
    expect(await mgr.isRunning()).toBe(true)

    const shell2 = createFakeShell({ containerRunning: false })
    const mgr2 = new PwnoContainerManager(undefined, shell2)
    expect(await mgr2.isRunning()).toBe(false)
  })

  test("allocateSessionId returns deterministic id from candidate", () => {
    const mgr = new PwnoContainerManager()
    expect(mgr.allocateSessionId("vuln_bof_main")).toBe("exploit-vuln_bof_main")
    expect(mgr.allocateSessionId("vuln_fmt_leak")).toBe("exploit-vuln_fmt_leak")
  })

  test("url reflects configured port", () => {
    const mgr = new PwnoContainerManager({ port: 5555 })
    expect(mgr.url).toBe("http://127.0.0.1:5555/mcp")
  })

  test("custom container name and image", async () => {
    const shell = createFakeShell({ containerRunning: false })
    const mgr = new PwnoContainerManager(
      { containerName: "my-pwno", image: "custom-image:v2" },
      shell,
    )

    await mgr.ensure()

    const runCmd = shell.commands.find((c) => c.includes("run"))
    expect(runCmd).toContain("my-pwno")
    expect(runCmd).toContain("custom-image:v2")
  })

  test("ensure mounts workspace path", async () => {
    const shell = createFakeShell({ containerRunning: false })
    const mgr = new PwnoContainerManager(undefined, shell)

    await mgr.ensure("/my/challenge/.omp")

    const runCmd = shell.commands.find((c) => c.includes("run"))
    expect(runCmd).toBeDefined()
    const vFlag = runCmd!.find((arg) => arg.includes("/my/challenge/.omp"))
    expect(vFlag).toBeDefined()
  })
})
