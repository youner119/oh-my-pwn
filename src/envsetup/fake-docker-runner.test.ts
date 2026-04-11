import { describe, expect, test } from "bun:test"
import {
  FakeDockerRunner,
  dockerEnoentError,
  type FakeDockerResponse,
} from "./fake-docker-runner"

describe("FakeDockerRunner", () => {
  test("records every call in order with args and opts", () => {
    const runner = new FakeDockerRunner(() => ({ exitCode: 0 }))
    runner.run(["build", "-t", "omp-abc", "."], { cwd: "/tmp/c" })
    runner.run(["image", "inspect", "omp-abc"])

    expect(runner.calls.length).toBe(2)
    expect(runner.calls[0]!.args).toEqual(["build", "-t", "omp-abc", "."])
    expect(runner.calls[0]!.opts.cwd).toBe("/tmp/c")
    expect(runner.calls[1]!.args).toEqual(["image", "inspect", "omp-abc"])
  })

  test("returns the responder's stdout/stderr as Buffers", () => {
    const runner = new FakeDockerRunner(() => ({
      exitCode: 0,
      stdout: "hello\n",
      stderr: "warning\n",
    }))
    const result = runner.run(["--version"])

    expect(result.exitCode).toBe(0)
    expect(result.stdout.toString("utf-8")).toBe("hello\n")
    expect(result.stderr.toString("utf-8")).toBe("warning\n")
  })

  test("dispatches based on argv pattern", () => {
    const runner = new FakeDockerRunner((call) => {
      if (call.args[0] === "image" && call.args[1] === "inspect") {
        return { exitCode: 1, stderr: "no such image\n" }
      }
      if (call.args[0] === "build") {
        return { exitCode: 0, stdout: "Successfully tagged x\n" }
      }
      const fail: FakeDockerResponse = { exitCode: 127 }
      return fail
    })

    expect(runner.run(["image", "inspect", "x"]).exitCode).toBe(1)
    expect(runner.run(["build", "."]).exitCode).toBe(0)
    expect(runner.run(["unknown"]).exitCode).toBe(127)
  })

  test("throws the configured spawn error (e.g., ENOENT for missing docker)", () => {
    const runner = new FakeDockerRunner(() => ({
      exitCode: 0,
      throwError: dockerEnoentError(),
    }))
    try {
      runner.run(["--version"])
      throw new Error("expected throw")
    } catch (err) {
      expect(err).toBeInstanceOf(Error)
      expect((err as NodeJS.ErrnoException).code).toBe("ENOENT")
    }
  })
})
