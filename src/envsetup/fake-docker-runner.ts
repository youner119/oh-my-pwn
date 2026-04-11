/**
 * In-memory {@link DockerRunner} implementation used exclusively by unit
 * tests in this directory. NOT exported from `index.ts`; production code
 * never imports it.
 *
 * Tests construct a {@link FakeDockerRunner} with a responder function that
 * pattern-matches on the docker arguments and returns a canned response.
 * Every call is also recorded in {@link FakeDockerRunner.calls} so tests can
 * assert that the correct sequence of docker invocations actually happened.
 *
 * Usage example:
 *
 *   const runner = new FakeDockerRunner((call) => {
 *     if (call.args[0] === "image" && call.args[1] === "inspect") {
 *       return { exitCode: 1, stderr: "no such image\n" }  // cache miss
 *     }
 *     if (call.args[0] === "build") {
 *       return { exitCode: 0, stdout: "Successfully tagged omp-abc:latest\n" }
 *     }
 *     throw new Error(`unexpected docker invocation: ${call.args.join(" ")}`)
 *   })
 *
 * @internal
 */

import type {
  DockerRunner,
  DockerRunOptions,
  DockerRunResult,
} from "./docker-runner"

export interface FakeDockerCall {
  args: readonly string[]
  opts: DockerRunOptions
}

export interface FakeDockerResponse {
  exitCode: number
  stdout?: Buffer | string
  stderr?: Buffer | string
  /**
   * If set, the runner throws this instead of returning a result. Used to
   * simulate spawn-level failures like docker missing (`code: "ENOENT"`).
   */
  throwError?: Error & { code?: string }
}

export type FakeDockerResponder = (call: FakeDockerCall) => FakeDockerResponse

export class FakeDockerRunner implements DockerRunner {
  readonly calls: FakeDockerCall[] = []

  constructor(private readonly responder: FakeDockerResponder) {}

  run(args: readonly string[], opts: DockerRunOptions = {}): DockerRunResult {
    const call: FakeDockerCall = { args, opts }
    this.calls.push(call)
    const response = this.responder(call)
    if (response.throwError !== undefined) {
      throw response.throwError
    }
    return {
      exitCode: response.exitCode,
      stdout: toBuffer(response.stdout),
      stderr: toBuffer(response.stderr),
    }
  }
}

/** Convenience: build an ENOENT error suitable for FakeDockerResponse.throwError. */
export function dockerEnoentError(): Error & { code: string } {
  const err = Object.assign(new Error("spawnSync docker ENOENT"), { code: "ENOENT" })
  return err
}

function toBuffer(value: Buffer | string | undefined): Buffer {
  if (value === undefined) {
    return Buffer.alloc(0)
  }
  if (typeof value === "string") {
    return Buffer.from(value, "utf-8")
  }
  return value
}
