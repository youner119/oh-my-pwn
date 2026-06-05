import { describe, expect, test } from "bun:test"

import { checkWriteAcl } from "./acl"

describe("checkWriteAcl (ACL Layer 2, per-tool)", () => {
  test("patch_state allows orchestrator + setup + reverser", () => {
    for (const id of ["orchestrator", "setup", "reverser"]) {
      expect(checkWriteAcl("patch_state", id)).toBeNull()
    }
  })

  test("patch_state denies VH / SA / Exploiter", () => {
    for (const id of ["vulnhunter", "strategist", "exploiter"]) {
      const d = checkWriteAcl("patch_state", id)
      expect(d?.error).toBe("acl_denied")
      expect(d?.agent_id).toBe(id)
    }
  })

  test("candidate writes + update_challenge are orchestrator-only", () => {
    const tools = [
      "create_candidate",
      "patch_candidate",
      "delete_candidate",
      "update_challenge",
    ] as const
    for (const tool of tools) {
      expect(checkWriteAcl(tool, "orchestrator")).toBeNull()
      for (const id of ["setup", "reverser", "vulnhunter"]) {
        expect(checkWriteAcl(tool, id)?.error).toBe("acl_denied")
      }
    }
  })

  test("register_challenge allows orchestrator + setup; denies others", () => {
    for (const id of ["orchestrator", "setup"]) {
      expect(checkWriteAcl("register_challenge", id)).toBeNull()
    }
    for (const id of ["reverser", "vulnhunter", "strategist", "exploiter"]) {
      expect(checkWriteAcl("register_challenge", id)?.error).toBe("acl_denied")
    }
  })

  test("unknown agent_id is denied", () => {
    const d = checkWriteAcl("patch_state", "attacker")
    expect(d?.error).toBe("acl_denied")
    expect(d?.agent_id).toBe("attacker")
  })
})
