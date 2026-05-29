# Database (SQLite + Drizzle ORM + 별개 DB MCP server)

> **Phase 1 — state/candidate → SQLite 이전.** Spec: `.omc/specs/deep-interview-database-mcp.md`.
> Phase 2 (binary artifacts / pagination / knowledge) 는 defer.

이 문서는 OmP의 **DB 영역 전체** — 박힌 결정, schema 영역, MCP server 영역, ACL 영역, migration 영역, 외부 접근 영역 — 정리합니다. 현 file-based IO (`state.json` + `candidate per-file`) 영역의 *완전 교체* 영역.

---

## 핵심 결정 (deep-interview, 2026-05-29)

1. **DB = SQLite (WAL mode)** — embedded, per-challenge file, Orchestrator sole writer invariant 자연 fit.
2. **Per-challenge file** — `<challenge>/.omp/state.db` (현 challenge-격리 모델 유지). Cross-challenge 2-tier 없음.
3. **완전 교체** — file-based 영역 (`state.json` + `candidates/*.json`) 폐기. SQLite = sole source-of-truth.
4. **별개 stdio MCP server** — `omp-db-mcp` (pwno-mcp / binja MCP 패턴). opencode 자동 spawn + tool discovery.
5. **DB 영역 plugin tool 6개 폐기** — agent 가 `mcp__omp-db__*` 직접 호출. 비 DB plugin tool 12개 유지.
6. **2 layer ACL** — Layer 1: agent config `tools` field (호출 표면 안 노출) + Layer 2: MCP server `agent_id` parameter 검증.
7. **Typed schema-aware 표면** — 6 typed tool (`read_state` / `patch_state` / `read_candidate` / `create_candidate` / `patch_candidate` / `delete_candidate`) — 1:1 mapping.
8. **ORM = Drizzle (bun:sqlite driver)** — DB-agnostic schema + migration runner + future DB 이전 invariant 박힘.
9. **Hybrid normalization** — stable nested object flatten + array 별개 FK 일관 + `etc` JSON column.

---

## DB file 영역

```
<challenge-dir>/
└── .omp/
    └── state.db          ← SQLite, WAL mode, per-challenge sole source-of-truth
    └── state.db-wal      ← WAL journal (자동)
    └── state.db-shm      ← shared memory (자동)
```

- **Path:** `<challenge>/.omp/state.db` (`state.json` + `candidates/*.json` 폐기).
- **Mode:** WAL (`PRAGMA journal_mode = WAL`) — reader-many writer-one.
- **Foreign keys:** `PRAGMA foreign_keys = ON` (CASCADE 동작 보장).
- **Atomic write:** POSIX rename 영역 안 박힘 → WAL transaction 영역. 다중 statement 박힌 영역 = explicit `BEGIN` / `COMMIT`.

---

## Schema 영역 (10 table)

박힌 영역 — `src/db/schema.ts` (Drizzle). zod schema (`src/state/challenge-state.ts`) 영역과 동기 유지.

### State 영역 (5 table)

| Table | 역할 | PK |
|---|---|---|
| `state` | 메인 row per challenge (40+ flatten column + `etc_json`) | `challenge_id` |
| `state_source_paths` | source 파일 경로 array | `(challenge_id, ord)` |
| `state_setup_blocker_candidates` | ambiguous-binary 후보 path array | `(challenge_id, ord)` |
| `state_corrections` | user correction log | `(challenge_id, ord)` |
| `state_extracted_libs` | NEEDED-library map (soname → path) | `(challenge_id, soname)` |

`state` table 박힌 영역 — **Hybrid normalization**:
- **Top-level scalars** (column) — `challenge_dir` / `binary_path` / `binary_input_path` / `dockerfile_path` / `source_present` / `challenge_type` / `setup_complete` / `unsupported_kind` / `libc_version` / `libc_path` / `ld_path` / `docker_image` / `pseudocode_dir` / `bndb_path` / `pipeline_phase` / `created_at` / `updated_at` / 등 25+
- **Mitigations** (flatten 6 column) — `mitigation_nx` / `mitigation_pie` / `mitigation_canary` / `mitigation_relro` / `mitigation_seccomp` / `mitigation_raw`
- **RemoteEntrypoint** (flatten 4 column) — `remote_host` / `remote_port` / `remote_wrapper` / `remote_command`
- **ParallelConfig** (flatten 4 column) — `parallel_vh_instance_count` / `parallel_sa_instance_count` / `parallel_max_cycles` / `parallel_max_retries_per_candidate`
- **SetupBlocker** (flatten 2 column + array) — `setup_blocker_kind` / `setup_blocker_message` (+ candidates → `state_setup_blocker_candidates`)
- **etc** (JSON column) — `etc_json` (다양한 환경 dump: kernel_* / source_* / library_* / multi_*)

### Candidate 영역 (5 table)

| Table | 역할 | PK |
|---|---|---|
| `candidates` | 메인 row per candidate (Summary + Detail merge, 15+ column) | `(challenge_id, id)` |
| `candidates_combined_from` | combined/derived candidate 의 source id array | `(challenge_id, candidate_id, ord)` |
| `candidates_gives` | verified primitive name array | `(challenge_id, candidate_id, ord)` |
| `candidates_needs` | required primitive name array | `(challenge_id, candidate_id, ord)` |
| `candidates_verification_blockers` | SA verify 실패 영역 (cause / suggested_fix / retry_recommended) | `(challenge_id, candidate_id, ord)` |

박힌 결정 — **Summary + Detail merge** (현 file 분리 영역 = `state.json[].vuln_candidates` + `.omp/candidates/<id>.json`):
- File 분리 동기 (tool result size cap) = SQLite **column SELECT** 박힘 영역에서 자연 해소
- `list_candidates(challenge_id)` = `SELECT summary_columns FROM candidates WHERE challenge_id = ?` (small)
- `read_candidate(id)` = `SELECT * FROM candidates WHERE id = ?` + array FK preload (Drizzle relations + `with: {...}`)

### Composite FK + CASCADE

모든 array FK table 박힘 — `(challenge_id, parent_id)` composite FK + `onDelete: cascade`. `candidates` row 삭제 시 4 array FK row 자동 삭제. `state` row 삭제 시 4 state array + candidates + 4 candidates array 영역 일관 삭제.

### `challenge_id` column 모든 table 박힘

박힌 이유 — *future server DB row-level isolation ready* + *명시적 audit* + *array table 영역에서 challenge_id 직접 query 자연*. Per-file 영역에서 redundant 영역 박힘 부담 (8 byte × row, 보통 < 1 KB) — 박힌 가치 박힘 큼.

---

## DB MCP server 영역 (`omp-db-mcp`)

### 구조

```
opencode (TUI) ─stdio─ omp-db-mcp (bun process)
                          ├─ bun:sqlite (per-challenge state.db open)
                          ├─ Drizzle ORM (relations + with preload)
                          └─ 6 typed tool 박힘
                              ├─ mcp__omp-db__read_state
                              ├─ mcp__omp-db__patch_state
                              ├─ mcp__omp-db__read_candidate
                              ├─ mcp__omp-db__create_candidate
                              ├─ mcp__omp-db__patch_candidate
                              └─ mcp__omp-db__delete_candidate
```

- **구현 위치 (T4 plan 영역):** OmP repo 안 `src/db-mcp/` package (별개 fork 안 함). `bun build src/db-mcp/index.ts --target bun --format esm` → stdio binary.
- **Lifecycle:** opencode 자동 spawn (`opencode.json` 의 `mcp.omp-db` entry). 종료 시 자동 정리.
- **Tool discovery:** Orchestrator 가 MCP `tools/list` 영역 자동 인지. agent prompt 박힌 영역 = `mcp__omp-db__*` 표면 직접 호출.

### Tool 표면 (typed schema-aware)

박힌 6 tool 박힘 영역 — 현 `omp_*` plugin tool 영역과 1:1 매핑 + `agent_id` parameter 추가:

| Plugin tool (현, 폐기) | MCP tool (Phase 1, 신설) | ACL Layer 2 |
|---|---|---|
| `omp_read_state(challenge_dir)` | `mcp__omp-db__read_state(challenge_id)` | open (모든 agent) |
| `omp_patch_state(challenge_dir, partial)` | `mcp__omp-db__patch_state(challenge_id, partial, agent_id)` | Orchestrator only |
| `omp_read_candidate(challenge_dir, id)` | `mcp__omp-db__read_candidate(challenge_id, id)` | open (모든 agent) |
| `omp_create_candidate(challenge_dir, candidate)` | `mcp__omp-db__create_candidate(challenge_id, candidate, agent_id)` | Orchestrator only |
| `omp_patch_candidate(challenge_dir, id, patch)` | `mcp__omp-db__patch_candidate(challenge_id, id, patch, agent_id)` | Orchestrator only |
| `omp_delete_candidate(challenge_dir, id)` | `mcp__omp-db__delete_candidate(challenge_id, id, agent_id)` | Orchestrator only |

### MCP handler 영역 (multi-table → single object)

박힌 영역 — handler 가 multi-table query 박힌 후 *합친 단일 typed object* 박혀 agent 박힘. Agent 입장 = *table 분리 transparent*, 박힌 표현 = 현 `VulnCandidate` / `ChallengeState` 와 1:1 동일.

```ts
// 예: read_candidate handler
const row = await db.query.candidates.findFirst({
  where: and(eq(candidates.id, id), eq(candidates.challengeId, challenge_id)),
  with: {
    combinedFrom: true,
    gives: { orderBy: ord },
    needs: { orderBy: ord },
    verificationBlockers: { orderBy: ord },
  },
})
return VulnCandidateSchema.parse(transformRowToVulnCandidate(row))
```

Drizzle `relations + with` 영역 박힘 = **1 query LEFT JOIN preload** (N+1 회피). SQLite 영역에서 ms 수준 — baseline 무관.

---

## ACL 2 layer

박힌 Orchestrator sole writer invariant 영역 (state-split P1-P6 의 핵심) 박힌 영역 — 별개 MCP server 박힘 영역에서 *agent identity 전달 메커니즘* 안 박히면 깨짐 → **2 layer defense**:

### Layer 1 — Agent config `tools` field (UI exposure)

- Sub-agent (VH / SA / Exploiter / Reverser) 의 agent config 에 *DB write tool 안 박힘* (`mcp__omp-db__patch_state` / `create_candidate` / `patch_candidate` / `delete_candidate`).
- opencode 가 *호출 표면 자체 안 노출* — sub-agent 가 *그 tool 박힌 영역 자체 모름*.
- Read tool (`mcp__omp-db__read_state` / `read_candidate`) 만 노출.
- 박힌 위치 — `src/orchestration/agent-tool-restrictions.ts` 영역.

### Layer 2 — MCP server `agent_id` parameter (server-side)

- Write tool 의 parameter 에 `agent_id: string` 강제 (typed schema 박힘).
- MCP server 가 검증 — Orchestrator 외 (예: `"vulnhunter"` / `"strategist"` / `"exploiter"` / `"reverser"`) → reject.
- Layer 1 박힌 영역이 *모든 합법 호출* 차단해도, Layer 2 박힌 영역이 *위조 / bypass* 영역 영영 reject.

---

## Migration 영역 (완전 교체)

박힌 결정 — **완전 교체** (사용자 명시, deep-interview Round 1):
- 기존 challenge 의 `state.json` + `candidates/*.json` → SQLite migration script 박힌 후 file 영역 삭제.
- 병행 운영 (dual-write) 안 함 — SQLite = sole source-of-truth.

### Migration script 영역 (T3 plan)

```
1. <challenge>/.omp/state.json 영역 → parse → ChallengeState zod validate
2. <challenge>/.omp/state.db 영역 박힘 (Drizzle migration runner)
3. state row insert (모든 column + array FK 영역)
4. candidates/*.json walk → 각 candidate row insert (+ array FK 영역)
5. 박힌 영역 검증 — re-read state via Drizzle → 영영 동등 박힘 확인
6. file 영역 삭제 — state.json + candidates/ 디렉토리
```

박힌 실패 영역 — transaction rollback (`BEGIN` ~ `COMMIT` 안). file 영역 삭제 = transaction commit 박힌 *후* 박힘 (rollback 영영 보장).

### Drizzle migration runner (T2 plan)

- `drizzle-kit generate` → `src/db/migrations/0000_*.sql` 박힘 (10 table + index 영역).
- Runtime — `migrate(db, { migrationsFolder: "src/db/migrations" })` from `drizzle-orm/bun-sqlite/migrator` 박힘.
- 매 DB file 첫 open 시점 박힘 (idempotent).

---

## 외부 read 채널

박힌 invariant — SQLite file 자체 박힌 *외부 process 영역 read-only 접근 가능* (WAL reader-many 보장).

```bash
sqlite3 -readonly <challenge>/.omp/state.db
sqlite> .schema
sqlite> SELECT id, primitive, verification_result FROM candidates;
sqlite> SELECT candidate_id FROM candidates_gives WHERE primitive_name = 'libc_base';
```

박힐 용도:
- **사용자 검토** — challenge 상태 영역 직접 확인 (현 `cat state.json` 편의 영역의 대체)
- **CLI / GUI tool** — DB browser (e.g., `sqlitebrowser`) 박힌 영역에서 row 단위 검토
- **Multi-process** — MCP server 가 write 박힌 중 외부 read 박힘 영역 OK (WAL)

**박힌 영역 — MCP server 가 stdio 박힌 영역 = opencode session 단일.** 외부 process 박힌 영역에서 *write* 박힐 필요 시 SQLite WAL 의 writer-one 제약 영역 박힘 — 영영 *MCP server 의 stdio 채널* 통해 박혀야 됨.

---

## Phase 2 (defer 영역)

박힌 영역 — 본 Phase 1 spec scope 박힌 영역 *제외*. 별개 spec 박힌 영역 박힘.

| 영역 | 박힐 영역 | 박힌 동기 |
|---|---|---|
| **Binary artifacts → SQLite BLOB** | libc / ld / Dockerfile / source 폴더 영역 의 SQLite BLOB (≤ 5MB) + content-addressable 외부 path (> 5MB) | 사용자 명시 영역 (deep-interview Round 7 박힘 영역에서 Simplifier mode 박힌 영역 defer) |
| **Pagination protocol** | read tool 응답 size > threshold 시 cursor / offset-limit 영역 | 실측 부재 영역 → premature 회피 |
| **Knowledge DB 이전** | vendor (ctf-pwn / ctf-reverse / how2heap) + notes + writeups → DB + FTS5 영역 | 동기 측정 부재 + 잃는 것 큼 (git diff / vim 편집 / vendor sync / prompt-embedded path) — 별개 spec |
| **소스코드 실행 history → DB** | Exploiter PoC / Reverser artifacts / output snapshot 영역 의 실행 + DB 영역 + 후속 참고 | 대상 + 후속 참고 의미 (cross-challenge α / within-challenge β) 모호 — 별개 spec |

---

## 박힌 task list (current-task.md)

| Group | Task | 영역 |
|---|---|---|
| DB schema + Migration | T1 ✅ | Drizzle schema (10 table) — eb9186c |
| | T2 | Drizzle migration runner (`drizzle-kit generate` + runtime `migrate()`) |
| | T3 | Migration script (state.json + candidates/*.json → SQLite + rollback) |
| DB MCP server (omp-db-mcp) | T4 | `src/db-mcp/` package + bun build → stdio binary |
| | T5 | 6 typed tool 박힘 (zod 검증) |
| | T6 | ACL Layer 2 — `agent_id` parameter 검증 |
| | T7 | `scripts/setup-omp.sh` + `opencode.json` 의 `mcp.omp-db` entry |
| Plugin tool 영역 폐기 | T8 | DB 영역 plugin tool 6개 폐기 |
| | T9 | ACL Layer 1 — sub-agent agent config `tools` field |
| Agent prompt 영역 | T10 | 5 agent prompt update — 호출 이름 변경 |
| 검증 | T11 | typecheck + test + build |
| | T12 | 1-cycle 실 challenge 검증 |
| | T13 | file 영역 폐기 cleanup |
| | T14 | 외부 read 채널 검증 (sqlite3) |
| Docs / 정합 | T15 | CLAUDE.md update — tool count 18 → 12 + DB MCP 6 |
| | T16 | docs/tools.md + docs/state-and-io.md update — DB MCP 영역 박힘 |
| | T17 | `.omc/state/backlog.md` 업데이트 — Phase 2 entry |

진행 상황 = `.omc/state/current-task.md`.

---

## 참조

- **Spec:** `.omc/specs/deep-interview-database-mcp.md`
- **Current task:** `.omc/state/current-task.md`
- **Source-of-truth (zod schema):** `src/state/challenge-state.ts` (DB schema 영역과 동기)
- **DB schema:** `src/db/schema.ts`
- **Drizzle config:** `drizzle.config.ts`
- **현 file IO 영역:** [`state-and-io.md`](state-and-io.md) (Phase 1 후 폐기)
- **Tool 영역:** [`tools.md`](tools.md) (Phase 1 후 18 → 12 + DB MCP 6)
- **Agents:** [`agents.md`](agents.md) (Phase 1 후 5 agent prompt 영역 update)
