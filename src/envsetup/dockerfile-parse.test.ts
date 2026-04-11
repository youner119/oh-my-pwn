import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { parseDockerfile, parseDockerfileText } from "./dockerfile-parse"

function makeTmp(label: string): string {
  const dir = join(
    tmpdir(),
    `omp-dockerfile-parse-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  )
  mkdirSync(dir, { recursive: true })
  return dir
}

describe("parseDockerfileText", () => {
  test("ynetd-wrapped CTF (typical Lv1 layout)", () => {
    const dockerfile = `
      FROM ubuntu:22.04
      RUN apt-get update && apt-get install -y ynetd
      COPY chall /chall
      EXPOSE 1337
      CMD ["ynetd", "-p", "1337", "/chall"]
    `
    const result = parseDockerfileText(dockerfile)

    expect(result.exposedPorts).toEqual([1337])
    expect(result.cmd).toContain("ynetd")
    expect(result.wrapper).toBe("ynetd")
    expect(result.hasSeccompFlag).toBe(false)
  })

  test("socat one-liner with shell-form CMD", () => {
    const dockerfile = `
      FROM ubuntu:20.04
      COPY chall /chall
      EXPOSE 9999/tcp
      CMD socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/chall
    `
    const result = parseDockerfileText(dockerfile)

    expect(result.exposedPorts).toEqual([9999])
    expect(result.wrapper).toBe("socat")
  })

  test("xinetd via ENTRYPOINT, no CMD", () => {
    const dockerfile = `
      FROM debian:bullseye
      RUN apt-get install -y xinetd
      EXPOSE 31337
      ENTRYPOINT ["/usr/sbin/xinetd", "-dontfork"]
    `
    const result = parseDockerfileText(dockerfile)

    expect(result.exposedPorts).toEqual([31337])
    expect(result.entrypoint).toContain("xinetd")
    expect(result.wrapper).toBe("xinetd")
  })

  test("plain CMD with no wrapper", () => {
    const dockerfile = `
      FROM alpine
      COPY chall /chall
      CMD ["/chall"]
    `
    const result = parseDockerfileText(dockerfile)

    expect(result.cmd).toContain("/chall")
    expect(result.wrapper).toBeUndefined()
    expect(result.exposedPorts).toEqual([])
  })

  test("multi-stage build picks up directives from the final stage", () => {
    const dockerfile = `
      FROM gcc:12 AS builder
      COPY chall.c /src/chall.c
      RUN gcc -o /src/chall /src/chall.c

      FROM ubuntu:22.04
      COPY --from=builder /src/chall /chall
      EXPOSE 4242
      CMD ["ncat", "-l", "-k", "4242", "-c", "/chall"]
    `
    const result = parseDockerfileText(dockerfile)

    expect(result.exposedPorts).toEqual([4242])
    expect(result.wrapper).toBe("ncat")
  })

  test("ENTRYPOINT takes precedence over CMD when both name a wrapper", () => {
    const dockerfile = `
      FROM ubuntu
      ENTRYPOINT ["ynetd", "-p", "1000"]
      CMD ["socat", "TCP-LISTEN:1000", "EXEC:/chall"]
    `
    const result = parseDockerfileText(dockerfile)

    expect(result.wrapper).toBe("ynetd")
  })

  test("seccomp hint matches --security-opt seccomp=", () => {
    const dockerfile = `
      FROM alpine
      # docker run --security-opt seccomp=policy.json ...
      CMD ["/chall"]
    `
    const result = parseDockerfileText(dockerfile)
    expect(result.hasSeccompFlag).toBe(true)
  })

  test("seccomp hint matches PR_SET_SECCOMP in RUN/source content", () => {
    const dockerfile = `
      FROM ubuntu
      RUN echo "binary uses prctl(PR_SET_SECCOMP) at startup" > /notes
      CMD ["/chall"]
    `
    const result = parseDockerfileText(dockerfile)
    expect(result.hasSeccompFlag).toBe(true)
  })

  test("seccomp hint matches bare 'seccomp' word", () => {
    const dockerfile = `
      FROM ubuntu
      RUN apt-get install -y libseccomp-dev
      CMD ["/chall"]
    `
    const result = parseDockerfileText(dockerfile)
    expect(result.hasSeccompFlag).toBe(true)
  })

  test("no seccomp hint when nothing in the file mentions it", () => {
    const dockerfile = `
      FROM alpine
      COPY chall /chall
      EXPOSE 1234
      CMD ["/chall"]
    `
    const result = parseDockerfileText(dockerfile)
    expect(result.hasSeccompFlag).toBe(false)
  })

  test("line continuations are unfolded so directives parse correctly", () => {
    const dockerfile = `
      FROM ubuntu
      RUN apt-get update && \\
          apt-get install -y \\
          ynetd
      EXPOSE 1337
      CMD ["ynetd", "-p", "1337", "/chall"]
    `
    const result = parseDockerfileText(dockerfile)
    expect(result.exposedPorts).toEqual([1337])
    expect(result.wrapper).toBe("ynetd")
  })

  test("wrapper recognises absolute paths via basename match", () => {
    const dockerfile = `
      FROM ubuntu
      EXPOSE 5555
      ENTRYPOINT ["/usr/bin/ynetd", "-p", "5555", "/chall"]
    `
    const result = parseDockerfileText(dockerfile)
    expect(result.wrapper).toBe("ynetd")
  })

  test("multiple EXPOSE directives produce ordered list", () => {
    const dockerfile = `
      FROM ubuntu
      EXPOSE 80 443
      EXPOSE 1337/tcp
      CMD ["/chall"]
    `
    const result = parseDockerfileText(dockerfile)
    expect(result.exposedPorts).toEqual([80, 443, 1337])
  })

  test("ignores comments and unknown directives", () => {
    const dockerfile = `
      # this is a comment
      FROM alpine
      LABEL maintainer="test"
      ARG VERSION=1.0
      ENV PATH=/usr/local/bin:/usr/bin
      EXPOSE 7777
      CMD ["/chall"]
    `
    const result = parseDockerfileText(dockerfile)
    expect(result.exposedPorts).toEqual([7777])
    expect(result.cmd).toContain("/chall")
  })
})

describe("parseDockerfile (file I/O)", () => {
  let dir: string

  beforeEach(() => {
    dir = makeTmp("file")
  })

  afterEach(() => {
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test("reads a real file from disk and parses it", () => {
    const path = join(dir, "Dockerfile")
    writeFileSync(
      path,
      `FROM ubuntu\nEXPOSE 1337\nCMD ["ynetd", "-p", "1337", "/chall"]\n`,
    )

    const result = parseDockerfile(path)
    expect(result.dockerfilePath).toBe(path)
    expect(result.exposedPorts).toEqual([1337])
    expect(result.wrapper).toBe("ynetd")
  })

  test("returns an empty result when the file does not exist (lenient)", () => {
    const path = join(dir, "missing-Dockerfile")
    const result = parseDockerfile(path)
    expect(result.dockerfilePath).toBe(path)
    expect(result.exposedPorts).toEqual([])
    expect(result.wrapper).toBeUndefined()
    expect(result.cmd).toBeUndefined()
    expect(result.entrypoint).toBeUndefined()
    expect(result.hasSeccompFlag).toBe(false)
  })
})
