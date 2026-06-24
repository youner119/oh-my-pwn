# Tools — OmP plugin tool 12개 + DB MCP `omp-db` tool 11개

이 문서는 OmP agent들이 사용하는 **tool 목록**과 각 tool의 **역할 / 시그니처 /
에러 케이스**를 정리합니다.

> **2026-06 database-mcp cutover:** state / candidate 의 read·write 는 plugin
> tool (`omp_read_state` 등 6개) 이 폐기되고 **별개 DB MCP server `omp-db`**
> (stdio) 의 `mcp__omp-db__*` tool 로 이전됐습니다. 본 문서는 그 6개 + challenge
> identity 5개를 호출 표면 위주로 함께 다루되, schema / ACL 2 layer / 외부 read
> 채널 등 DB 영역 전반은 **`docs/database.md`** 가 정본입니다.

---

## 왜 tool로 뽑는가

OmP의 기본 원칙: **deterministic 작업은 library로, creative reasoning은
agent로.** LLM은 판단이 필요한 곳에서 빛나고, 반복적·기계적 작업에서는
library가 우월합니다. Tool은 agent와 library를 잇는 인터페이스입니다.

예를 들어 `docker build → libc 추출 → patchelf` 파이프라인은:
- 결정적 (같은 input → 같은 output)
- LLM이 추론으로 재현할 수 없음 (ELF magic byte를 LLM이 직접 parse하면 틀림)
- 실패 케이스가 명확 (docker not running, libc not found 등)

각 단계는 atomic tool (`omp_setup_docker_build`, `omp_setup_extract_file`,
`omp_setup_patch_elf`, `omp_setup_verify_runtime`) 로 분리되어 있고,
이를 호출하는 흐름 제어는 **omp-setup agent** (LLM) 가 담당합니다.
Polymorphic 입력 (kernel / library-only / multi-binary / source-only 등)
의 분류는 LLM 판단이 필요하지만, 각 phase 의 state-changing operation
자체는 deterministic 해야 하므로 분리.

(이전 `omp_run_envsetup` 단일 tool 은 omp-setup agent + atomic tool
4개로 대체됨 — T12. Spec: `.omc/specs/deep-interview-envsetup-agent.md`.)

반대로 "어느 함수를 `safe_input_copy`라고 이름 짓는다"는 LLM 고유 판단이라
tool로 만들지 않고 agent prompt에서 자연어로 처리합니다.

---

## 현재 tool — 한 눈에

### plugin tool 12개 (`src/tools/*.ts` + `src/orchestration/*.ts`, `src/plugin.ts` 등록)

| Tool | 역할 | Library-backed? | 읽기/쓰기 |
|---|---|---|---|
| `omp_load_challenge` | Challenge 폴더 부트스트랩 (`.omp/` 초기화 + `state.workspace_root` 시드, **non-DB** — state row 시드는 db-mcp `register_challenge`). binary/dockerfile/source 식별은 omp-setup Phase 0 (Detect) — `.omc/specs/contract-load-detect-split.md` D1. | Yes (loader) | 쓰기 |
| `omp_append_journal` | `journal.md` append | Yes | 쓰기 |
| `omp_get_template` | 템플릿 문자열 로드 | Yes (src/templates) | 읽기 |
| `omp_verify_template_output` | 템플릿 작성물 구조 검증 | Yes | 읽기 (idempotent) |
| `omp_task_launch` | 단일 sub-agent를 **fire-and-forget**으로 spawn. `{task_id, session_id}` 즉시 반환. `agent`는 category alias (`setup`/`reverser`/`vulnhunter`/`strategist`/`exploiter`) 또는 full name (`omp-*`). | Yes (orchestration/) | 쓰기 |
| `omp_task_wait_all` | 주어진 `task_ids[]` **모두** terminal에 도달할 때까지 block. 입력 순서대로 `results[]` 반환. unknown id는 synthetic failed outcome (graceful). | Yes (orchestration/) | 읽기 |
| `omp_task_wait_any` | 주어진 `task_ids[]` 중 **첫 완료자** + `remaining_ids` 반환. 성공/실패/취소 모두 first-complete로 취급. SA race + dynamic spawn에 사용. | Yes (orchestration/) | 읽기 |
| `omp_task_cancel` | `task_ids[]`를 best-effort 취소 (멱등). `{cancelled[], not_found[]}` 반환. SDK `session.abort` 호출 + `status="cancelled"` + `done` emit. | Yes (orchestration/) | 쓰기 |
| `omp_setup_docker_build` | (omp-setup 전용) Phase 1 — challenge Dockerfile build. `image_tag` policy: hint 우선, 없으면 `omp-<sha8 of binary_input_sha256>`. `force_rebuild` 옵션. | Yes (envsetup/docker-build) | 쓰기 |
| `omp_setup_extract_file` | (omp-setup 전용) Phase 3 (image → `.omp/artifacts/`) + Phase 5 (`.omp/artifacts/` → `workspace/<id>/`). `source = "image"` (docker cp) 또는 `"host"` (fs.copyFile). `dereference_symlinks` 옵션. | Yes (envsetup/docker-extract) | 쓰기 |
| `omp_setup_patch_elf` | (omp-setup 전용) Phase 3 + Phase 5. Binary case (dst_path + interpreter + replacements) 또는 Library case (in-place + replacements). `--replace-needed`로 SONAME → 절대경로 rewrite (RUNPATH 미사용 — D3). | Yes (envsetup/patch-elf, 신규 `patchElf` 함수) | 쓰기 |
| `omp_setup_verify_runtime` | (omp-setup 전용) Phase 4 (`mode=host`) + 옵셔널 Phase 5 (`mode=container`). Host: process spawn + timeout=ok semantics + missing-lib regex. Container: docker run -d + TCP probe. `keep_container_on_fail` 옵션. | Yes (신규) | 읽기 |

### DB MCP `omp-db` tool 11개 (`src/db-mcp/`, stdio, `mcp__omp-db__*` 호출)

write tool 은 `agent_id` 인자 + ACL Layer 2 allowlist 강제. signature 는 모두 surrogate `challenge_id` 키 (dir 아님). 상세 schema/ACL/외부 read 는 `docs/database.md`.

| Tool | 역할 | 호스트 | ACL (write) |
|---|---|---|---|
| `mcp__omp-db__read_state` | `state.db` 로드 (`challenge_id`). `vuln_candidates` 는 *summary array* (detail 미포함). | DB MCP | open (모든 agent) |
| `mcp__omp-db__patch_state` | `state.db` 부분 업데이트 (Zod validated, tx). `vuln_candidates[]` detail field 박힘 시 reject (`vuln_candidates_detail_in_summary_patch`). | DB MCP | {orchestrator, setup, reverser} |
| `mcp__omp-db__read_candidate` | `candidates` table 로드 (id) → summary + detail array FK preload. **모든 agent read.** | DB MCP | open |
| `mcp__omp-db__create_candidate` | 신규 candidate 박음 — summary row + detail array 한 tx. **Orchestrator 전용.** | DB MCP | {orchestrator} |
| `mcp__omp-db__patch_candidate` | 기존 candidate 의 `{summary?, detail?}` 부분 갱신 (한 tx). **Orchestrator 전용.** | DB MCP | {orchestrator} |
| `mcp__omp-db__delete_candidate` | candidate row + detail cascade 삭제. **Orchestrator 전용.** | DB MCP | {orchestrator} |
| `mcp__omp-db__register_challenge` | dir → surrogate `<name>_<uuid8>` mint + 초기 state row. 중복 dir → `challenge_exists` reject (순수 등록, idempotency 는 lookup 책무). | DB MCP | {orchestrator, setup} |
| `mcp__omp-db__lookup_challenge` | dir → `challenge_id` 조회 (read-only). 미등록 → `found:false`. fresh vs reload 분기 판정. | DB MCP | open |
| `mcp__omp-db__read_challenge` | catalog row 조회 (`challenge_id` → dir / name / category / status). thread-through 로 sub-agent 가 dir 회수. | DB MCP | open |
| `mcp__omp-db__update_challenge` | catalog status / notes 갱신. **Orchestrator 전용.** | DB MCP | {orchestrator} |
| `mcp__omp-db__delete_challenge` | challenge row 1개 DELETE → state + candidates cascade. fresh restart 흐름. **Orchestrator 전용.** | DB MCP | {orchestrator} |

plugin tool 은 `src/tools/*.ts` / `src/orchestration/*.ts` 구현 + `src/plugin.ts` session 등록. 원래 7개 + M5 병렬 인프라 + pwno 호환성 수정 + 4-tool cutover (2026-05-18). 이후 BN 전환으로 `omp_save_decompiled` 제거, pwno 호환성 수정으로 `omp_pwno_container` 제거. **envsetup 재설계 (T12-T14)** 로 `omp_run_envsetup` / `omp_stage_challenge` / `omp_pwno_status` 3개 폐지 + omp-setup atomic 4개 흡수. **state split P3 (2026-05-24)** 로 candidate 가 summary↔detail 분리. **database-mcp cutover (2026-06)** 로 state/candidate plugin tool 6개 폐기 → DB MCP `omp-db` 로 이전 + challenge identity 5 tool 신설 (spec `.omc/specs/deep-interview-database-mcp.md` Phase 1 + `challenge-identity-catalog.md`).

---

## `omp_load_challenge`

**용도:** 새 challenge 폴더를 처음 로드할 때 `.omp/` 디렉토리를 부트스트랩.
binary / Dockerfile / source 식별은 **하지 않는다** — 그건 omp-setup Phase 0
(Detect) 의 책임. **state row 도 만들지 않는다 (non-DB, T20)** — 그건 db-mcp
`register_challenge` 책무. 본 tool 은 디렉토리 존재 검증 + `.omp/{journal.md,
artifacts/, logs/, exploit/}` 초기화 + `workspace_root` 반환만 수행. spec:
`.omc/specs/contract-load-detect-split.md` (D1).

**Arguments:**
```ts
{
  challenge_dir: string       // 절대경로 (예: /tmp/ctf/chall1)
}
```

binary / dockerfile arg 는 contract 변경으로 제거됨 (구버전 prompt 가 남아
있다면 갱신 필요).

**성공 응답:**
```json
{
  "ok": true,
  "workspace_root": "/tmp/ctf/chall1/.omp",
  "freshlyInitialized": false
}
```

`freshlyInitialized`: `.omp/journal.md` 가 이 호출 이전에 없었는지 (= 첫 로드).
Reload시 `false`. state 는 반환하지 않음 — 이후 orchestrator 가
`lookup_challenge` → (fresh 면) setup `register_challenge` → `read_state`
로 회수. binary 교체 시 sha drift 감지는 폐지 — `rm -rf .omp/` 후 reload
가 정본 (D4).

**에러 케이스:**
- `missing-dir` — 폴더 존재하지 않음
- `not-a-directory` — 경로가 파일임

binary 후보 0개 / 2개 이상, Dockerfile 부재, ELF magic 검증 등은 모두
omp-setup Phase 0 (Detect) 가 처리. ELF 후보 여러 개면 setup 이
`state.setup_blocker = {kind: "ambiguous-binary", candidates[], message}` 박고
stop → orchestrator 가 사용자 disambig 받아 `mcp__omp-db__patch_state` 로
`binary_input_path` 박고 blocker clear → setup 재시작 (D5).

**사용 맥락:** Orchestrator pipeline 의 **Stage 0 (Load)** — 매 challenge
의 첫 tool 호출. 재실행 시 idempotent: 기존 `.omp/` 검증만 (state 는
db-mcp `lookup_challenge` 로 회수).

**파일:** `src/tools/omp-load-challenge.ts`, backed by
`src/loader/load-challenge-folder.ts`

---

## `omp_setup_*` (omp-setup agent 전용 atomic 4개)

`omp_setup_docker_build`, `omp_setup_extract_file`, `omp_setup_patch_elf`,
`omp_setup_verify_runtime` 네 atomic tool 은 **omp-setup agent 만** 호출.
각 tool 의 시그너처 / 에러 케이스 / 사용 패턴은 spec 정본 참조:

- 디자인 결정 + tool 시그너처: `.omc/specs/deep-interview-envsetup-agent.md`
  § D4 (Tool surface), § Architecture (Phase 1-5 흐름)
- 구현: `src/tools/omp-setup-{docker-build,extract-file,patch-elf,verify-runtime}.ts`
- 호출 흐름 (Phase 0-6) 은 omp-setup agent prompt
  (`src/agents/omp-setup.ts`) 에 박혀 있음

폐지된 legacy tool (이 자리에 있었던 `omp_run_envsetup`) 의 책임은:
- Docker build → `omp_setup_docker_build` (omp-setup Phase 1)
- libc/ld 추출 → `omp_setup_extract_file` source="image" (Phase 3)
- patchelf → `omp_setup_patch_elf` (Phase 3 host + Phase 5 workspace,
  `--replace-needed` 방식, RUNPATH 미사용)
- 호스트 검증 → `omp_setup_verify_runtime` mode="host" (Phase 4)

폐지된 `omp_stage_challenge` 책임 (workspace 복사 + patchelf) 은
`omp_setup_extract_file` source="host" + `omp_setup_patch_elf` workspace
모드 (Phase 5) 가 흡수. 폐지된 `omp_pwno_status` 책임 (컨테이너
sanity) 은 omp-setup agent 가 Phase 5 에서 bash (`docker ps` + `curl`)
로 직접 호출.

---

## `mcp__omp-db__read_state`

**용도:** 현재 challenge의 state 읽기 (`state.db`). Agent가 매 session/stage
시작 시 맨 먼저 호출해서 "지금 어디까지 왔는지" 파악. (옛 plugin `omp_read_state` 폐기.)

**Arguments:**
```ts
{ challenge_id: string }   // surrogate id (dir 아님). lookup_challenge / read_challenge 로 회수
```

**성공 응답:**
```json
{ "ok": true, "state": { /* ChallengeState 전체 (multi-table → nested object) */ } }
```

**에러 케이스:**
- `state_not_found` — `challenge_id` 의 state row 없음 (register_challenge 먼저)
- `state_corrupt` — row 는 있는데 Zod schema 재조립 실패
- `internal_error` — 기타

**사용 맥락:** 모든 OmP agent의 **첫 호출**. Required sequence에 명시:
```
1. mcp__omp-db__read_state(challenge_id) — get binary_path, source_present, ...
```

**파일:** `src/db-mcp/server.ts` (read_state handler) + `src/db-mcp/mapper.ts` (Drizzle relations → nested JSON)

---

## `mcp__omp-db__patch_state`

**용도:** state 의 특정 필드만 부분 업데이트 (`state.db`). Shallow merge 후 Zod
재검증, 실패 시 row 건드리지 않음. 성공 시 한 transaction. **write tool — `agent_id` 필수** (ACL Layer 2 = {orchestrator, setup, reverser}). (옛 plugin `omp_patch_state` 폐기.)

**Arguments:**
```ts
{
  challenge_id: string
  patch: Record<string, unknown>   // 부분 ChallengeState 필드
  agent_id: string                 // ACL allowlist 대조
}
```

**예시:**
```json
{
  "challenge_id": "chall1_a1b2c3d4",
  "patch": {
    "reverser_summary_path": "/tmp/ctf/chall1/.omp/artifacts/reverser-analysis.md",
    "reverser_analyzed_at": "2026-04-15T06:01:00.239Z"
  },
  "agent_id": "reverser"
}
```

**Protected fields:** `challenge_id`, `schema_version` 등 identity/version 키는
patch 대상 아님 (challenges catalog 의 dir 도 `update_challenge` 채널). 그 외
필드는 patchable — `binary_input_path` / `binary_input_sha256` /
`dockerfile_path` / `source_present` / `source_paths` 는 omp-setup Phase 0
(Detect) 가 쓰고, orchestrator 도 D5 disambig 시 `binary_input_path` 박음. spec:
`.omc/specs/contract-load-detect-split.md` D2/D6.

**`etc` write 정책 (POLICY-ENFORCED, D7):** `etc` (free-form
`Record<string, unknown>`) 는 strip 대상이 *아니지만* 정책상 **omp-setup /
omp-orchestrator 만 write 가능**. omp-reverser / omp-vulnhunter /
omp-strategist / omp-exploiter 는 read 만 — patch 에 `etc` 포함시키면
orchestrator audit 이 잡고 revert. 위반 누적 시 physical enforcement
(patch_state.context.agent 확인) 로 escalate.

**`vuln_candidates` summary-only contract (state-split-vuln-candidates.md
D2/D3):** `mcp__omp-db__patch_state` 의 `patch.vuln_candidates[]` 는 summary field
(`id`, `verification_result`, `primitive`, `agent`, `combined_from`,
`description`, `gives_count`, `needs_count`, `has_poc`) 만 수락. detail
field (`rationale`, `verification_blockers`, `gives`, `needs`,
`poc_script_path`, `location`, `libc_range`, `origin_type`,
`derived_from`, `confidence`) 박힘 시 `error:
"vuln_candidates_detail_in_summary_patch"` 로 reject — detail 갱신은
`mcp__omp-db__patch_candidate` 채널 사용. summary + detail 동시 갱신도 별개 tool.

**성공 응답:** 업데이트된 전체 state.

**에러 케이스:**
- `state_not_found` — loader 먼저 실행 필요
- `state_corrupt` — 로드 자체 실패
- `validation_error` — merge된 state가 Zod schema 검증 실패. detail에
  `issues` (Zod 오류 리스트)
- `save_failed` — 디스크 쓰기 실패

**사용 맥락:**
- Envsetup / Reverser / VulnHunter / Exploiter 등 모든 agent가 작업 완료
  후 결과를 state에 기록
- User correction을 orchestrator가 반영할 때
- 예: Reverser가 마지막에 3개 path + timestamp를 한 번의 `mcp__omp-db__patch_state`로
  기록

**파일:** `src/db-mcp/server.ts` (patch_state handler) + `src/db-mcp/acl.ts` (agent_id allowlist)

---

## `mcp__omp-db__read_candidate` / `create_candidate` / `patch_candidate` / `delete_candidate`

**용도:** `vuln_candidates` 의 summary↔detail 분리 tool 4종 (옛 plugin
`omp_*_candidate` 폐기). state row 는 summary array 만 박고, detail
(rationale / verification_blockers / gives / needs / poc_script_path /
location / 등) 은 **DB candidates table + array FK** 에 정규화 (옛
`.omp/candidates/<id>.json` per-file storage 폐기 — database-mcp cutover).
Spec: `.omc/specs/state-split-vuln-candidates.md` D2/D3 + `docs/database.md`.

### ACL — Orchestrator sole writer (2 layer)

| Tool | 호출 허용 | 비고 |
|---|---|---|
| `mcp__omp-db__read_candidate` | 모든 agent | read 는 sole writer 정책 무관 |
| `mcp__omp-db__create_candidate` | **Orchestrator 전용** | sub-agent 호출 시 `acl_denied` |
| `mcp__omp-db__patch_candidate` | **Orchestrator 전용** | sub-agent 호출 시 `acl_denied` |
| `mcp__omp-db__delete_candidate` | **Orchestrator 전용** | sub-agent 호출 시 `acl_denied` |

ACL enforcement = 2 layer: (L1) `src/orchestration/agent-tool-restrictions.ts`
가 sub-agent config 에서 write tool surface 자체 제거 + (L2) `src/db-mcp/acl.ts`
의 `agent_id` allowlist 가 server-side 강제. VH / SA / Exploiter 가 write tool
호출하면 reject.

Sub-agent 는 *state 영역 write 자체 안 함*. 결과는 task return value 로 보고
(D3.1) — `{candidate_id, summary_changes?, detail_changes?, new_candidate?}`
형식. Orchestrator 가 `omp_task_wait_*` 로 결과 수령 후 적절한 candidate
tool 호출.

### `mcp__omp-db__read_candidate`

**Arguments:**
```ts
{ challenge_id: string, id: string }
```

**성공 응답:** `{ ok: true, candidate: VulnCandidate }` — summary + detail
array FK preload merge 형태 (`VulnCandidateSchema = VulnCandidateSummary.merge(VulnCandidateDetail)`).

**에러:** `candidate_not_found` / `candidate_corrupt` / `invalid_candidate_id` / `internal_error`.

### `mcp__omp-db__create_candidate`

**Arguments:**
```ts
{
  challenge_id: string
  candidate: VulnCandidate    // summary + detail 전체
  agent_id: string            // ACL — {orchestrator}
}
```

summary row + detail array 가 한 transaction 으로 박힘. id 중복 시 `candidate_id_collision`.

**에러:** `acl_denied` (sub-agent) / `candidate_id_collision` / `invalid_candidate_id` / `validation_error` / `save_failed`.

### `mcp__omp-db__patch_candidate`

**Arguments:**
```ts
{
  challenge_id: string
  id: string
  patch: {
    summary?: Partial<VulnCandidateSummary>   // summary row 갱신
    detail?: Partial<VulnCandidateDetail>     // detail array 갱신
  }
  agent_id: string                            // ACL — {orchestrator}
}
```

summary + detail 둘 다 박혔으면 한 transaction 에서 양쪽 갱신.

**에러:** `acl_denied` (sub-agent) / `candidate_not_found` / `invalid_candidate_id` / `validation_error` / `save_failed`.

### `mcp__omp-db__delete_candidate`

**Arguments:**
```ts
{ challenge_id: string, id: string, agent_id: string }   // ACL — {orchestrator}
```

candidate row + detail array cascade 삭제 (idempotent — 부재 시 no-op).

**에러:** `acl_denied` (sub-agent) / `invalid_candidate_id` / `save_failed`.

### 사용 맥락

- **VulnHunter 결과 흡수** — VH ensemble return 의 `new_candidate` → Orchestrator 가 `mcp__omp-db__create_candidate`.
- **SA verify 결과 흡수** — SA return 의 `summary_changes` + `detail_changes` → Orchestrator 가 `mcp__omp-db__patch_candidate`.
- **SA combine derived candidate** — SA return 의 `new_candidate` (combined_from 박힘) → Orchestrator 가 `mcp__omp-db__create_candidate`.
- **SA invalidate** — SA 가 candidate 가 invalid 라고 판단 → return 으로 보고 → Orchestrator 가 `mcp__omp-db__delete_candidate`.

**파일:** `src/db-mcp/server.ts` (candidate handlers) + `src/db-mcp/mapper.ts` (table↔nested) + `src/db-mcp/acl.ts`. (옛 `src/state/io.ts` 의 `loadCandidate`/`saveCandidate`/`deleteCandidate` 는 T22 에서 제거.)

---

## `omp_append_journal`

**용도:** `journal.md`에 새 섹션 append. heading은 자동 timestamp.

**Arguments:**
```ts
{
  challenge_dir: string
  heading: string          // 섹션 제목 (## 없이). 예: "Reverser analysis complete"
  body: string             // markdown body. 표, 리스트, 코드 블록 허용
}
```

**Heading format:**
```
## <heading> — <ISO timestamp>
```
ISO timestamp는 tool이 자동 주입 (agent가 위조 불가).

**성공 응답:** `{ "ok": true }`

**에러 케이스:** `journal_write_failed` — 드물지만 디스크 write 실패 시

**사용 맥락:** Agent가 user-readable progress 기록할 때마다:
- EnvSetup 완료 후
- Reverser 분석 완료 후
- User correction 발생 시 (heading: "User correction")
- 실패 케이스: "Reverser skipped — cached" / "Reverser self-review failed at Pass A"
- BN MCP 연결 실패: "BN MCP not reachable on port 9009"

**주의:** Agent는 절대 `write` / `edit` tool로 `journal.md`를 직접 건드리지
않음. 이 tool 경유만.

**파일:** `src/tools/omp-append-journal.ts`

---

## `omp_get_template`

**용도:** Agent가 template-based artifact를 작성할 때 템플릿 로드. 템플릿은
`## Rules for filling this template` (template-local 규칙) + `## Skeleton`
(markdown 스켈레톤) 구조.

**Arguments:**
```ts
{
  kind: string   // "reverser-research-en" | "reverser-research-ko" | "list"
}
```

**특별 값 `kind: "list"`:** 현재 등록된 모든 template kind 반환. 에이전트가
"어떤 템플릿이 있는지" 묻는 용도.

**성공 응답:**
```json
{
  "ok": true,
  "kind": "reverser-research-en",
  "template": "# Template: reverser-research-en\n\n## Rules for filling this template\n\n..."
}
```

`kind: "list"` 응답:
```json
{
  "ok": true,
  "kinds": ["reverser-research-en", "reverser-research-ko"]
}
```

**에러 케이스:** `unknown_template` — 해당 kind 없음, response에 `available`
리스트 포함

**사용 맥락:** Reverser가 EN/KO 연구 보고서 작성 직전. Required sequence
step 14/15:
```
14a. omp_get_template("reverser-research-en") → read rules, fill skeleton
14b. write → reverser-research.md
14c. omp_verify_template_output(...) → 검증 + 재시도
```

**왜 tool로 뽑았는가:** 자세한 근거는 [agents.md](agents.md)의
"Cross-cutting vs template-local 규칙 분리" 섹션 참조. 요약: template-local
규칙은 LLM의 recency bias로 오히려 tool 응답으로 받는 게 adherence가 좋고,
VulnHunter/Exploiter도 같은 infrastructure 재사용 가능.

**파일:** `src/tools/omp-get-template.ts`, backed by `src/templates/index.ts`

---

## `omp_verify_template_output`

**용도:** Agent가 template-based artifact를 쓴 뒤 **구조 compliance 기계
검증**. 5개 check:

1. **필수 섹션 존재** — 템플릿의 skeleton에서 H2 heading 추출, 각각이
   output에 등장하는지 검사. Korean 템플릿은 `## Executive summary (요약)`
   같은 옵션 parenthetical도 허용.
2. **미치환 `<...>` placeholder 없음** — regex 매칭, HTML 태그 등
   false-positive 회피
3. **영문 forbidden words 부재** — `vulnerability`, `exploit`, `primitive`,
   `BOF`, `overflow`, `UAF` 등 unambiguous vuln vocabulary. Common modals
   (`may`, `likely`, `could`)는 일부러 제외 (false positive 방지)
4. **한국어 forbidden words 부재** (KO 템플릿만) — `취약점`, `익스플로잇`,
   `오버플로우`, `유출`, `누출`, `악용` 등
5. **한국어 기술용어 번역 부재** (KO 템플릿만) — `스택`, `힙`, `캐나리`,
   `카나리`, `버퍼` 등 영문 유지 기술용어가 번역됐는지

**Arguments:**
```ts
{
  kind: string        // "reverser-research-en" | "reverser-research-ko"
  content: string     // 검증할 markdown content 전문
}
```

**성공 응답 (pass):**
```json
{ "ok": true, "kind": "reverser-research-en" }
```

**실패 응답 (violations):**
```json
{
  "ok": false,
  "kind": "reverser-research-ko",
  "violations": [
    {
      "severity": "error",
      "kind": "missing_section",
      "message": "Required section \"## Handoff notes\" not found in output",
      "detail": { "section": "Handoff notes" }
    },
    {
      "severity": "error",
      "kind": "forbidden_ko_word",
      "message": "Forbidden Korean vulnerability vocabulary appears in output: 취약점",
      "detail": { "words": ["취약점"] }
    },
    {
      "severity": "error",
      "kind": "ko_technical_translation",
      "message": "Korean translation of English technical term(s) found — these must stay in English: 스택, 버퍼",
      "detail": { "words": ["스택", "버퍼"] }
    }
  ]
}
```

**Retry policy (agent prompt에 명시):** 최대 2회 재시도.
1. 첫 write → verify → violations 있으면 violation list 보고 수정 → 재write
2. 2번째 verify → 여전히 violations면 → 재수정
3. 3번째 verify도 실패면 → artifact header에 `(VERIFICATION FAILED —
   STRUCTURAL ISSUES REMAIN)` prepend + journal에 violation 기록 + 진행

**중요한 것:** 이 tool은 **mechanical structural check만** 합니다.
"purpose paragraph가 정말 pseudocode와 일치하는가" 같은 semantic check는
Reverser의 Pass B가 별도로 담당.

**Length check 없음:** 사용자 명시 결정 ("프로그램이 커지면 800단어로
부족할 수 있잖아"). 길이는 템플릿 rules의 soft guideline으로만 언급.

**에러 케이스:**
- `unknown_template` — kind config 없음
- `template_not_found` — 템플릿 string 자체 빌드 issue

**사용 맥락:** Reverser Required sequence step 14d / 15d. 모든 template-based
write 직후.

**미래 확장:** VulnHunter가 `vulnhunter-candidates` 템플릿을 만들면 그
kind에 맞는 config (다른 forbidden words — VulnHunter는 exploit 언어 **허용**,
오히려 structural neutral-ese 금지 가능)를 추가. Exploiter도 마찬가지.

**파일:** `src/tools/omp-verify-template-output.ts`, `src/templates/index.ts`

---

## Tool 추가하려면?

1. **`src/tools/<tool-name>.ts` 생성** — `tool()` helper로 `ToolDefinition`
   반환
2. **`src/tools/index.ts`에 export 추가**
3. **`src/plugin.ts`의 `tool` map에 등록** — `omp_<tool_name>: <toolRef>`
4. **`bun run build:plugin`** + **`omp` 재시작**
5. **(옵션) 테스트** — 대부분의 OmP tool은 thin wrapper라 library 단위
   테스트만 있고 tool 자체 단위 테스트는 없음. 필요 시 추가

**Tool 시그니처 패턴** (현재 모든 tool이 따름):

```ts
import { tool, type ToolDefinition } from "@opencode-ai/plugin/tool"

export const ompSomethingTool: ToolDefinition = tool({
  description: "What this tool does, when to call it, ...",
  args: {
    challenge_dir: tool.schema.string().describe("Absolute path..."),
    // other args
  },
  execute: async ({ challenge_dir, ... }) => {
    try {
      const result = /* library call */
      return JSON.stringify({ ok: true, ...result })
    } catch (err) {
      if (err instanceof SomeDomainError) {
        return JSON.stringify({
          error: err.kind,
          message: err.message,
          detail: err.detail,
        })
      }
      return JSON.stringify({ error: "internal_error", message: String(err) })
    }
  },
})
```

**Tool 응답은 항상 JSON string**. `JSON.stringify` 사용. Agent는 이걸
파싱해서 `ok`/`error` 필드로 분기. 이 convention은 모든 OmP tool이 일관되게
따름.

---

## 관련 파일 요약

| 파일 | 역할 |
|---|---|
| `src/tools/index.ts` | plugin tool re-export (12개 — load + journal + 2 template + 4-tool task + 4-tool omp_setup_*) |
| `src/tools/omp-*.ts` | 각 plugin tool 구현 (thin wrapper over library 또는 omp-setup atomic) |
| `src/db/` | Drizzle schema (10 table) + migration runner + `openDb` (bun:sqlite, WAL). `state.db` = repo-root 글로벌 single DB |
| `src/db-mcp/` | 별개 DB MCP server `omp-db` — `server.ts` (11 tool) + `mapper.ts` (table↔nested JSON) + `acl.ts` (Layer 2 agent_id allowlist). `dist/db-mcp.js` |
| `src/orchestration/index.ts` | task surface (`omp_task_*` 4개) re-export |
| `src/orchestration/agent-tool-restrictions.ts` | per-agent tool ACL Layer 1 (`mcp__omp-db__*` write tool 의 sub-agent surface 제거) |
| `src/plugin.ts` | plugin tool map 등록 (session 레벨). DB tool 은 별개 MCP server (opencode.json `mcp.omp-db`) |
| `src/loader/` | load-challenge backed |
| `src/envsetup/` | docker-build / docker-extract / patch-elf library — atomic omp_setup_* 가 wrap (legacy `run-envsetup.ts` 437 줄은 T19 deprecation 영역) |
| `src/state/` | ChallengeState schema + `append_journal` backed + `io.ts` (`initializeOmpDir` / `getStatePaths`). state/candidate IO 는 DB 로 이전 (T22 제거) |
| `src/templates/` | get_template backed (템플릿 string 저장소) |
| `src/agents/omp-setup.ts` | atomic 4개 호출 흐름 제어 (Phase 0-6) |

다음 문서에서 **템플릿 시스템의 세부**를 다룹니다 → [templates.md](templates.md).
