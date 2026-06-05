import { describe, expect, test } from "bun:test"

import { checkWriteAcl } from "./acl"

describe("checkWriteAcl (ACL Layer 2)", () => {
  test("allows the sole writer (orchestrator)", () => {
    expect(checkWriteAcl("orchestrator")).toBeNull()
  })

  test("denies a known non-orchestrator agent", () => {
    for (const id of ["vulnhunter", "strategist", "exploiter", "reverser"]) {
      const d = checkWriteAcl(id)
      expect(d?.error).toBe("acl_denied")
      expect(d?.agent_id).toBe(id)
    }
  })

  test("denies an unknown agent_id", () => {
    const d = checkWriteAcl("attacker")
    expect(d?.error).toBe("acl_denied")
    expect(d?.message).toContain("Unknown agent_id")
  })
})
