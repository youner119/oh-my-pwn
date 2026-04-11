import { describe, expect, test } from "bun:test"
import { GhidraBridgeError } from "./errors"
import { createGhidraMcpClient } from "./client"

describe("createGhidraMcpClient", () => {
  describe("validation errors before I/O", () => {
    test("connect with stdio config missing command throws not-configured", async () => {
      const client = createGhidraMcpClient()
      let thrown: unknown
      try {
        await client.connect({ type: "stdio" })
      } catch (err) {
        thrown = err
      }
      expect(thrown).toBeInstanceOf(GhidraBridgeError)
      expect((thrown as GhidraBridgeError).kind).toBe("not-configured")
    })

    test("connect with sse config missing url throws not-configured", async () => {
      const client = createGhidraMcpClient()
      let thrown: unknown
      try {
        await client.connect({ type: "sse" })
      } catch (err) {
        thrown = err
      }
      expect(thrown).toBeInstanceOf(GhidraBridgeError)
      expect((thrown as GhidraBridgeError).kind).toBe("not-configured")
    })
  })

  describe("pre-connect guard", () => {
    test("callTool before connect throws connection-closed", async () => {
      const client = createGhidraMcpClient()
      let thrown: unknown
      try {
        await client.callTool("test", {})
      } catch (err) {
        thrown = err
      }
      expect(thrown).toBeInstanceOf(GhidraBridgeError)
      expect((thrown as GhidraBridgeError).kind).toBe("connection-closed")
    })

    test("listTools before connect throws connection-closed", async () => {
      const client = createGhidraMcpClient()
      let thrown: unknown
      try {
        await client.listTools()
      } catch (err) {
        thrown = err
      }
      expect(thrown).toBeInstanceOf(GhidraBridgeError)
      expect((thrown as GhidraBridgeError).kind).toBe("connection-closed")
    })
  })

  describe("initial state", () => {
    test("isConnected returns false before connect", () => {
      const client = createGhidraMcpClient()
      expect(client.isConnected()).toBe(false)
    })

    test("disconnect before connect does not throw", async () => {
      const client = createGhidraMcpClient()
      await expect(client.disconnect()).resolves.toBeUndefined()
    })
  })
})
