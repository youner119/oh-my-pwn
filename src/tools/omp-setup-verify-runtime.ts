/**
 * omp_setup_verify_runtime — Phase 4 / Phase 5 of omp-setup agent.
 *
 * Verify that a patched binary actually runs in its target environment.
 *
 * Two modes:
 *
 *   - mode="host" — Spawn `<binary_path>` on the host directly. If ld
 *     resolves every NEEDED successfully, the process either runs (and
 *     blocks on stdin / does work) or exits cleanly. If ld fails, the
 *     process exits immediately with a non-zero code and an
 *     "error while loading shared libraries" / "cannot open shared object
 *     file" message on stderr. We wait `timeout_ms`; an immediate non-zero
 *     exit is a fail signal, a still-running process at timeout is a
 *     success signal (ld resolved everything and the binary is doing work).
 *
 *   - mode="container" — `docker run -d --rm -p 0:<container_port> <image>`
 *     then poll the assigned host port with TCP connect. This mirrors how
 *     the challenge is actually used (pwntools `remote(host, port)` against
 *     the production deployment). Success = TCP connect within `timeout_ms`.
 *
 * D8 policy: diagnose-only, retry 0. Every result (success and failure)
 * carries an `evidence` block with stdout/stderr/docker_logs / inspect /
 * missing_libs. Every result also carries `reproduce_commands` — shell
 * snippets the user can copy-paste to reproduce or dig further.
 *
 * D8 extension (T08 — keep_container_on_fail): when container verify fails
 * AND `keep_container_on_fail=true`, the container is left running so the
 * user can `docker exec -it <name>` into it. Default false (clean cleanup).
 */

import { spawn as childSpawn } from "node:child_process"
import { existsSync } from "node:fs"
import { isAbsolute } from "node:path"
import { createConnection } from "node:net"
import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"
import {
  realDockerRunner,
  type DockerRunner,
} from "../envsetup/docker-runner"

/* ── DI seams ────────────────────────────────────────────────────────── */

export interface AsyncSpawnResult {
  exit_code: number | null
  signal: string | null
  stdout: Buffer
  stderr: Buffer
  timed_out: boolean
  spawn_error?: { code?: string; message: string }
}

export type AsyncSpawnFn = (
  cmd: string,
  args: readonly string[],
  timeoutMs: number,
) => Promise<AsyncSpawnResult>

export type TcpProbeFn = (
  host: string,
  port: number,
  timeoutMs: number,
) => Promise<boolean>

export interface OmpSetupVerifyRuntimeToolOptions {
  /** Inject a fake docker runner for tests (container mode). */
  runner?: DockerRunner
  /** Inject a fake process spawn for tests (host mode). */
  processSpawn?: AsyncSpawnFn
  /** Inject a fake TCP probe for tests (container mode). */
  tcpProbe?: TcpProbeFn
}

/* ── real defaults ───────────────────────────────────────────────────── */

const HEAD_BYTES = 4096

const realProcessSpawn: AsyncSpawnFn = async (cmd, args, timeoutMs) => {
  return new Promise<AsyncSpawnResult>((resolve) => {
    let stdout = Buffer.alloc(0)
    let stderr = Buffer.alloc(0)
    let exited = false
    let timedOut = false

    let child
    try {
      child = childSpawn(cmd, args as string[], { stdio: ["pipe", "pipe", "pipe"] })
    } catch (err) {
      resolve({
        exit_code: null,
        signal: null,
        stdout,
        stderr,
        timed_out: false,
        spawn_error: {
          code: (err as NodeJS.ErrnoException).code,
          message: (err as Error).message,
        },
      })
      return
    }

    child.on("error", (err) => {
      if (exited) return
      exited = true
      clearTimeout(timer)
      resolve({
        exit_code: null,
        signal: null,
        stdout,
        stderr,
        timed_out: timedOut,
        spawn_error: {
          code: (err as NodeJS.ErrnoException).code,
          message: err.message,
        },
      })
    })

    child.stdout?.on("data", (chunk: Buffer) => {
      if (stdout.length < HEAD_BYTES) {
        stdout = Buffer.concat([stdout, chunk])
      }
    })
    child.stderr?.on("data", (chunk: Buffer) => {
      if (stderr.length < HEAD_BYTES) {
        stderr = Buffer.concat([stderr, chunk])
      }
    })

    const timer = setTimeout(() => {
      timedOut = true
      try {
        child.kill("SIGTERM")
      } catch {
        // ignore
      }
      setTimeout(() => {
        try {
          child.kill("SIGKILL")
        } catch {
          // ignore
        }
      }, 500)
    }, timeoutMs)

    child.on("exit", (code, signal) => {
      if (exited) return
      exited = true
      clearTimeout(timer)
      resolve({
        exit_code: code,
        signal,
        stdout,
        stderr,
        timed_out: timedOut,
      })
    })
  })
}

const realTcpProbe: TcpProbeFn = (host, port, timeoutMs) => {
  return new Promise<boolean>((resolve) => {
    const sock = createConnection({ host, port })
    let settled = false
    const settle = (value: boolean) => {
      if (settled) return
      settled = true
      try {
        sock.destroy()
      } catch {
        // ignore
      }
      resolve(value)
    }

    const timer = setTimeout(() => settle(false), timeoutMs)
    sock.once("connect", () => {
      clearTimeout(timer)
      settle(true)
    })
    sock.once("error", () => {
      clearTimeout(timer)
      settle(false)
    })
  })
}

/* ── tool factory ────────────────────────────────────────────────────── */

const MISSING_LIB_PATTERNS: readonly RegExp[] = [
  // ld stderr: "<binary>: error while loading shared libraries: libfoo.so.1: cannot open shared object file"
  /([^\s:/]+\.so(?:\.[0-9]+)*): cannot open shared object file/gu,
  // ldd output: "libfoo.so.1 => not found"
  /([^\s/]+\.so(?:\.[0-9]+)*) => not found/gu,
]

function extractMissingLibs(stderr: string): string[] {
  const found = new Set<string>()
  for (const pat of MISSING_LIB_PATTERNS) {
    pat.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = pat.exec(stderr)) !== null) {
      if (m[1] !== undefined) found.add(m[1])
    }
  }
  return Array.from(found)
}

function randomContainerSuffix(): string {
  // 8 chars from base36, padded.
  return Math.random().toString(36).slice(2, 10).padEnd(8, "0")
}

function head(buf: Buffer): string {
  return buf.slice(0, HEAD_BYTES).toString("utf-8")
}

export function createOmpSetupVerifyRuntimeTool(
  options: OmpSetupVerifyRuntimeToolOptions = {},
): ToolDefinition {
  const runner = options.runner ?? realDockerRunner
  const processSpawn = options.processSpawn ?? realProcessSpawn
  const tcpProbe = options.tcpProbe ?? realTcpProbe

  return tool({
    description:
      "Verify a patched binary actually loads + runs in its target environment. " +
      "mode='host' spawns the binary on the host (timeout=ok means ld resolved); " +
      "mode='container' runs `docker run -d --rm -p 0:<container_port> <image>` " +
      "then TCP-probes the ephemeral host port to confirm the challenge service " +
      "is reachable (mirrors how pwntools remote() interacts with the deployment). " +
      "Returns { ok, mode, evidence, reproduce_commands } — D8 policy: diagnose-only, " +
      "retry 0. Set keep_container_on_fail=true to leave the failed container running " +
      "so the user can `docker exec -it` into it for manual diagnosis.",
    args: {
      binary_path: tool.schema
        .string()
        .describe(
          "Absolute host path to the patched binary. Required for mode='host'; " +
            "used only for reproduce_commands display in mode='container'.",
        ),
      mode: tool.schema
        .string()
        .describe('Verification mode: "host" or "container".'),
      image_tag: tool.schema
        .string()
        .optional()
        .describe(
          "Docker image tag for mode='container'. Required for container mode.",
        ),
      container_binary_path: tool.schema
        .string()
        .optional()
        .describe(
          'Absolute container path to the binary (e.g. "/workspace/<id>/prob"). ' +
            "Used in reproduce_commands display for mode='container'.",
        ),
      container_port: tool.schema
        .number()
        .optional()
        .describe(
          "Container-internal port that the challenge service listens on (from state.remote.port). " +
            "Required for mode='container'.",
        ),
      timeout_ms: tool.schema
        .number()
        .optional()
        .describe(
          "Wall-clock timeout for the verification run. Default 2000ms (host), 5000ms (container).",
        ),
      keep_container_on_fail: tool.schema
        .boolean()
        .optional()
        .describe(
          "When mode='container' and verify fails, leave the container running so the user can " +
            "`docker exec -it <name>` into it. Default false (always cleanup). The reproduce_commands " +
            "field will include the container name + host port when this is true.",
        ),
    },
    execute: async ({
      binary_path,
      mode,
      image_tag,
      container_binary_path,
      container_port,
      timeout_ms,
      keep_container_on_fail,
    }) => {
      try {
        if (mode !== "host" && mode !== "container") {
          return errorJson({
            error: "invalid_mode",
            message: `mode must be "host" or "container"; got "${String(mode)}".`,
          })
        }
        if (!isAbsolute(binary_path)) {
          return errorJson({
            error: "binary_not_absolute",
            message: `binary_path must be absolute; got "${binary_path}".`,
          })
        }

        if (mode === "host") {
          return await verifyHost(binary_path, timeout_ms ?? 2000, processSpawn)
        }

        // mode === "container"
        if (image_tag === undefined || image_tag === "") {
          return errorJson({
            error: "image_tag_required",
            message: 'image_tag is required when mode="container".',
          })
        }
        if (container_port === undefined) {
          return errorJson({
            error: "container_port_required",
            message:
              'container_port is required when mode="container" (derive from state.remote.port).',
          })
        }
        return await verifyContainer({
          binary_path,
          image_tag,
          container_binary_path,
          container_port,
          timeoutMs: timeout_ms ?? 5000,
          keepOnFail: keep_container_on_fail === true,
          runner,
          tcpProbe,
        })
      } catch (err) {
        return errorJson({
          error: "internal_error",
          message: String(err),
        })
      }
    },
  })
}

/* ── mode=host ───────────────────────────────────────────────────────── */

async function verifyHost(
  binaryPath: string,
  timeoutMs: number,
  processSpawn: AsyncSpawnFn,
): Promise<string> {
  if (!existsSync(binaryPath)) {
    return errorJson({
      error: "source_missing",
      message: `binary_path does not exist: ${binaryPath}`,
    })
  }

  const result = await processSpawn(binaryPath, [], timeoutMs)
  const stderr_head = head(result.stderr)
  const stdout_head = head(result.stdout)
  const missing_libs = extractMissingLibs(stderr_head)

  // Decision logic:
  //   - spawn_error (ENOENT / EACCES): fail
  //   - timed_out (still running) → ok (ld resolved, binary doing work)
  //   - exited within timeout + missing_libs present → fail
  //   - exited within timeout + non-zero code with ld error pattern → fail
  //   - exited cleanly within timeout → ok (small binary, OK)
  const reproduceCommands = [
    `ldd '${binaryPath}'`,
    `readelf -d '${binaryPath}' | head -40`,
    `'${binaryPath}' 2>&1 | head -20`,
  ]

  if (result.spawn_error !== undefined) {
    return JSON.stringify({
      ok: false,
      mode: "host",
      evidence: {
        stdout_head,
        stderr_head,
        exit_code: null,
        signal: null,
        timed_out: false,
        missing_libs,
        spawn_error: result.spawn_error,
      },
      reproduce_commands: reproduceCommands,
    })
  }

  const ok = result.timed_out || (missing_libs.length === 0 && result.exit_code === 0)

  return JSON.stringify({
    ok,
    mode: "host",
    evidence: {
      stdout_head,
      stderr_head,
      exit_code: result.exit_code,
      signal: result.signal,
      timed_out: result.timed_out,
      missing_libs,
    },
    reproduce_commands: reproduceCommands,
  })
}

/* ── mode=container ──────────────────────────────────────────────────── */

interface ContainerVerifyInputs {
  binary_path: string
  image_tag: string
  container_binary_path?: string
  container_port: number
  timeoutMs: number
  keepOnFail: boolean
  runner: DockerRunner
  tcpProbe: TcpProbeFn
}

async function verifyContainer(
  inputs: ContainerVerifyInputs,
): Promise<string> {
  const containerName = `omp-verify-${randomContainerSuffix()}`

  // Step 1: docker run -d --rm -p 0:<container_port> --name <name> <image>
  let runResult
  try {
    runResult = inputs.runner.run([
      "run",
      "-d",
      "--rm",
      "--name",
      containerName,
      "-p",
      `0:${inputs.container_port}`,
      inputs.image_tag,
    ])
  } catch (err) {
    return errorJson({
      error: "docker-not-available",
      message: `Failed to spawn docker: ${(err as Error).message}`,
    })
  }
  if (runResult.exitCode !== 0) {
    return errorJson({
      error: "docker-run-failed",
      message: `docker run failed (exit ${runResult.exitCode}).`,
      detail: {
        stderr: runResult.stderr.toString("utf-8").slice(0, HEAD_BYTES),
      },
    })
  }

  const containerId = runResult.stdout.toString("utf-8").trim()
  if (containerId === "") {
    return errorJson({
      error: "docker-run-failed",
      message: "docker run -d returned empty container id.",
    })
  }

  // Container is now running (or about to crash). Track whether cleanup
  // should happen — kept on success (always cleanup) or on fail when
  // keep_container_on_fail is false.
  let cleanupNeeded = true

  try {
    // Step 2: docker inspect to extract the ephemeral host port.
    let inspectResult
    try {
      inspectResult = inputs.runner.run(["inspect", containerId])
    } catch (err) {
      return errorJson({
        error: "docker-inspect-failed",
        message: `docker inspect failed: ${(err as Error).message}`,
      })
    }
    if (inspectResult.exitCode !== 0) {
      return errorJson({
        error: "docker-inspect-failed",
        message: `docker inspect exit ${inspectResult.exitCode}.`,
      })
    }

    const hostPort = parseHostPort(
      inspectResult.stdout.toString("utf-8"),
      inputs.container_port,
    )

    // Step 3: TCP probe with retry until timeout.
    const probeStart = Date.now()
    const probeInterval = 200
    let connectAttempts = 0
    let connected = false
    while (Date.now() - probeStart < inputs.timeoutMs) {
      connectAttempts += 1
      if (hostPort !== null) {
        connected = await inputs.tcpProbe(
          "127.0.0.1",
          hostPort,
          Math.min(probeInterval, inputs.timeoutMs),
        )
        if (connected) break
      }
      // Brief delay before next attempt.
      await new Promise<void>((r) => setTimeout(r, probeInterval))
    }

    const reproduceBase: string[] = []
    if (inputs.container_binary_path !== undefined) {
      reproduceBase.push(
        `# binary path inside container: ${inputs.container_binary_path}`,
      )
    }

    if (connected) {
      // success — cleanup runs
      return JSON.stringify({
        ok: true,
        mode: "container",
        evidence: {
          container_name: containerName,
          host_port: hostPort,
          container_port: inputs.container_port,
          connect_attempts: connectAttempts,
        },
        reproduce_commands: [
          ...reproduceBase,
          `docker run -d --rm -p 0:${inputs.container_port} ${inputs.image_tag}`,
          `nc 127.0.0.1 ${hostPort}`,
        ],
      })
    }

    // fail path — gather diagnostics
    let dockerLogs = ""
    let containerState = "unknown"
    try {
      const logsResult = inputs.runner.run(["logs", containerId])
      dockerLogs = logsResult.stdout.toString("utf-8")
      if (logsResult.stderr.length > 0) {
        dockerLogs = `${dockerLogs}\n=== stderr ===\n${logsResult.stderr.toString("utf-8")}`
      }
    } catch {
      // ignore — container may have already disappeared
    }
    try {
      const inspect2 = inputs.runner.run([
        "inspect",
        "-f",
        "{{.State.Status}}",
        containerId,
      ])
      if (inspect2.exitCode === 0) {
        containerState = inspect2.stdout.toString("utf-8").trim()
      }
    } catch {
      // ignore
    }

    const reproduce: string[] = [...reproduceBase]
    if (inputs.keepOnFail) {
      cleanupNeeded = false  // leave container running
      reproduce.push(
        `# Container left running for manual inspection (keep_container_on_fail=true):`,
        `docker exec -it ${containerName} sh`,
        `docker logs ${containerName}`,
        hostPort !== null ? `nc 127.0.0.1 ${hostPort}` : `# no host port mapping detected`,
        `# When done debugging:`,
        `docker stop ${containerName}`,
      )
    } else {
      reproduce.push(
        `# Container has been stopped. To reproduce + inspect:`,
        `docker run -it --rm --name ${containerName} -p 0:${inputs.container_port} ${inputs.image_tag} sh`,
        `# then in another shell:`,
        `nc 127.0.0.1 <newly-allocated-host-port>`,
      )
    }

    return JSON.stringify({
      ok: false,
      mode: "container",
      evidence: {
        container_name: containerName,
        host_port: hostPort,
        container_port: inputs.container_port,
        connect_attempts: connectAttempts,
        container_state: containerState,
        docker_logs_head: dockerLogs.slice(0, HEAD_BYTES),
        kept_for_debug: inputs.keepOnFail,
      },
      reproduce_commands: reproduce,
    })
  } finally {
    if (cleanupNeeded) {
      try {
        inputs.runner.run(["stop", containerId])
      } catch {
        // ignore — container may have already exited
      }
    }
  }
}

function parseHostPort(
  inspectJson: string,
  containerPort: number,
): number | null {
  try {
    const data = JSON.parse(inspectJson)
    const item = Array.isArray(data) ? data[0] : data
    const ports = item?.NetworkSettings?.Ports as Record<
      string,
      Array<{ HostPort?: string }> | null
    > | undefined
    if (!ports) return null
    // Key looks like "8080/tcp"; try both tcp and udp.
    const candidates = [`${containerPort}/tcp`, `${containerPort}/udp`]
    for (const key of candidates) {
      const arr = ports[key]
      if (arr && arr.length > 0) {
        const hp = arr[0]?.HostPort
        if (hp !== undefined) {
          const n = Number(hp)
          if (!Number.isNaN(n)) return n
        }
      }
    }
    return null
  } catch {
    return null
  }
}

/* ── helpers ─────────────────────────────────────────────────────────── */

function errorJson(payload: {
  error: string
  message: string
  detail?: unknown
}): string {
  return JSON.stringify({ ok: false, ...payload })
}
