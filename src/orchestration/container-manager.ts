/**
 * PwnoContainerManager — single pwno-mcp Docker container lifecycle.
 *
 * pwno-mcp supports multiple simultaneous debug sessions in one container
 * (each with its own GDB subprocess via session_id). So we only need ONE
 * container for all parallel Exploiter instances.
 *
 * Orchestrator calls:
 *   1. ensure() — start container if not running, return URL
 *   2. allocateSessionId(candidateId) — get unique session_id for an Exploiter
 *   3. stop() — cleanup after pipeline completes
 */

const DEFAULT_CONTAINER_NAME = "omp-pwno"
const DEFAULT_PORT = 5500
const DEFAULT_IMAGE = "ghcr.io/pwno-io/pwno-mcp:latest"

export interface PwnoContainerConfig {
  containerName?: string
  port?: number
  image?: string
  /** Absolute path to mount as /workspace in the container. */
  workspacePath?: string
}

export interface ContainerStatus {
  running: boolean
  url: string
  containerName: string
}

/** Shell command runner — injectable for testing. */
export interface ShellRunner {
  run(cmd: string[]): Promise<{ exitCode: number; stdout: string; stderr: string }>
}

/** Default shell runner using Bun.spawn. */
export const defaultShellRunner: ShellRunner = {
  async run(cmd: string[]) {
    const proc = Bun.spawn(cmd, {
      stdout: "pipe",
      stderr: "pipe",
    })
    const [stdout, stderr] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ])
    const exitCode = await proc.exited
    return { exitCode, stdout: stdout.trim(), stderr: stderr.trim() }
  },
}

export class PwnoContainerManager {
  private readonly containerName: string
  private readonly port: number
  private readonly image: string
  private readonly shell: ShellRunner
  private workspacePath: string

  constructor(config?: PwnoContainerConfig, shell?: ShellRunner) {
    this.containerName = config?.containerName ?? DEFAULT_CONTAINER_NAME
    this.port = config?.port ?? DEFAULT_PORT
    this.image = config?.image ?? DEFAULT_IMAGE
    this.workspacePath = config?.workspacePath ?? "/tmp/omp-workspace"
    this.shell = shell ?? defaultShellRunner
  }

  /** Get the MCP URL for this container. */
  get url(): string {
    return `http://127.0.0.1:${this.port}/mcp`
  }

  /**
   * Ensure the pwno-mcp container is running.
   * If already running, returns immediately. If not, starts it.
   */
  async ensure(workspacePath?: string): Promise<ContainerStatus> {
    if (workspacePath) this.workspacePath = workspacePath

    const running = await this.isRunning()
    if (running) {
      return { running: true, url: this.url, containerName: this.containerName }
    }

    // Remove stale container if exists (stopped but not removed)
    await this.shell.run(["docker", "rm", "-f", this.containerName]).catch(() => {})

    const result = await this.shell.run([
      "docker", "run", "-d",
      "--name", this.containerName,
      "-p", `${this.port}:5500`,
      "--cap-add=SYS_PTRACE",
      "--cap-add=SYS_ADMIN",
      "--security-opt", "seccomp=unconfined",
      "-v", `${this.workspacePath}:/workspace`,
      this.image,
    ])

    if (result.exitCode !== 0) {
      throw new Error(
        `Failed to start pwno-mcp container: ${result.stderr || result.stdout}`,
      )
    }

    // Brief wait for MCP server to initialize
    await sleep(1000)

    return { running: true, url: this.url, containerName: this.containerName }
  }

  /** Stop and remove the container. */
  async stop(): Promise<void> {
    await this.shell.run(["docker", "stop", this.containerName]).catch(() => {})
    await this.shell.run(["docker", "rm", "-f", this.containerName]).catch(() => {})
  }

  /** Check if the container is currently running. */
  async isRunning(): Promise<boolean> {
    const result = await this.shell.run([
      "docker", "inspect", "-f", "{{.State.Running}}", this.containerName,
    ])
    return result.exitCode === 0 && result.stdout === "true"
  }

  /**
   * Allocate a unique session_id for a candidate.
   * Each Exploiter uses this session_id in all pwno-mcp calls.
   */
  allocateSessionId(candidateId: string): string {
    return `exploit-${candidateId}`
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
