# State & I/O — `.omp/` 레이아웃과 데이터 흐름

이 문서는 OmP가 **어떻게 상태를 저장하고**, **어떤 산출물을 만들고**, 사람이
**어디를 읽고 어떻게 개입**하는지 정리합니다.

> **2026-06 database-mcp cutover:** `state` 와 `vuln_candidates` 는 옛
> `.omp/state.json` + `.omp/candidates/*.json` per-file storage 에서 **repo-root
> 글로벌 single SQLite `state.db`** (별개 DB MCP server `omp-db`) 로 이전됐습니다.
> 본 문서의 **스키마 (ChallengeState 필드) / sole-writer 정책 / journal / artifacts**
> 영역은 그대로 유효하되, 저장 매체가 file → DB 로 바뀐 부분을 반영합니다. DB file
> 위치 / 10 table schema / mapper / ACL 2 layer / 외부 read 채널은 **`docs/database.md`**
> 가 정본입니다.

---

## 핵심 원칙

1. **state / candidate 는 repo-root `state.db` (글로벌 single DB), journal /
   artifacts / logs / exploit 는 각 challenge 폴더 `.omp/`.** cutover 전엔 모든
   상태가 폴더 `.omp/` 안에 있었으나, 이제 machine-truth state 는 DB 로 분리됨.
   challenge 는 surrogate `challenge_id = "<name>_<uuid8>"` 로 식별 (dir 은 mutable
   컬럼) — 폴더를 옮겨도 `lookup_challenge(dir)` 로 재연결. 폴더 tar 이전 시
   artifacts/journal 은 따라가지만 DB state 는 새 머신에서 재등록 (catalog).
2. **`state.db` 가 machine-truth, `journal.md` 는 human-readable.**
   State 는 Zod-validated (DB row ↔ nested object), journal 은 append-only markdown.
3. **사람은 journal만 읽음. 수정은 prompt 채널로만.** `vim journal.md`
   같은 파일 직접 편집은 지원하지 않음. 사용자가 correction을 prompt로
   말하면 orchestrator가 `mcp__omp-db__patch_state`로 state를 고치고
   `journal.md`에 correction 블록을 append.
4. **Agent는 state를 직접 쓰지 않음.** 반드시 `mcp__omp-db__read_state` /
   `mcp__omp-db__patch_state` / `omp_append_journal` tool 경유.
5. **병렬 환경에서 Orchestrator가 sole writer.** 병렬 실행되는
   StrategyAgent/Exploiter는 `patch_state`를 호출하지 않고 결과만
   반환. Orchestrator가 수집 후 순차적으로 state에 반영. 동시 쓰기
   충돌 방지 (+ ACL Layer 2 가 server-side 강제). (`read_state`로 읽기는 가능.)

---

## 레이아웃 — repo-root `state.db` + challenge 폴더 `.omp/`

```
<repo-root>/
└── state.db                      ← 글로벌 single SQLite (state + candidate, 모든 challenge). OMP_DB_PATH. spec: database.md

<challenge-dir>/
├── prob                          ← binary (원본 또는 patchelf로 교체된 버전)
├── Dockerfile                    ← remote 재현용
├── chal.c                        ← (선택) C 소스 — 있으면 Reverser skip
└── .omp/                         ← OmP 산출물 (state/candidate 는 DB 로 이전 — 여기 없음)
    ├── journal.md                ← append-only progress log (read-only for humans)
    ├── artifacts/                ← agent-생성 산출물
    │   ├── libc.so.6             ← docker image에서 추출한 libc
    │   ├── ld-linux-x86-64.so.2  ← docker image에서 추출한 ld
    │   ├── prob.orig             ← patchelf 전 원본 binary (백업)
    │   ├── reverser-analysis.md  ← Reverser 구조화 artifact (VulnHunter 주 context)
    │   ├── reverser-research.md  ← Reverser 영문 narrative 연구 보고서
    │   └── reverser-research.ko.md ← Reverser 한국어 연구 보고서
    ├── logs/                     ← 빌드 / 실행 로그
    │   └── docker-build-*.log
    └── exploit/                  ← Exploiter pwntools scripts (병렬 시 candidate별 서브디렉토리)
```

`state` / `candidate` 는 `state.db` 의 정규화 table (summary row + detail array FK)
에 박힘 — 옛 `.omp/state.json` minified + `.omp/candidates/<id>.json` per-file 은
폐기. DB row 조립은 `mcp__omp-db__read_state` / `read_candidate` 가 multi-table →
nested object 로 수행.

`.omp/` 의 journal/artifacts/logs/exploit 서브디렉토리는 `omp_load_challenge` 의
`initializeOmpDir`가 load 시 자동으로 생성합니다 (state.json 시드는 안 함 — T20).

---

## ChallengeState 스키마 (`state.db`)

`src/state/challenge-state.ts`의 Zod schema가 single source of truth.
주요 필드를 그룹별로:

### Identification (loader T03가 채움)

| 필드 | 타입 | 설명 |
|---|---|---|
| `schema_version` | `"1"` | 스키마 버전 상수 |
| `challenge_dir` | string | challenge 폴더 절대경로 |
| `binary_path` | string? | patched binary 절대경로 (omp-setup Phase 3 산출) |
| `binary_sha256` | string? | patched binary 의 sha |
| `binary_input_path` | string? | 원본 input binary 절대경로 — omp-setup Phase 0 (Detect) 가 시드. no-binary 케이스 (kernel-pwn / source-only 등) 는 undefined |
| `binary_input_sha256` | string? | 원본 binary sha — 정보용 (drift idempotency 폐지, D4) |
| `dockerfile_path` | string? | Dockerfile 절대경로 — Phase 0 시드. Dockerfile 없는 challenge 는 undefined (D3) |
| `source_present` | boolean | C 소스 존재 여부 — Phase 0 시드 |
| `source_paths` | string[] | 발견된 소스 파일 경로들 |
| `setup_blocker` | `{kind:"ambiguous-binary", candidates[], message}?` | omp-setup Phase 0 가 ELF 후보 2+ 발견 시 박는 handoff signal. orchestrator 가 사용자 disambig 받아 해소 (D5) |
| `etc` | `Record<string, unknown>?` | 자유 형식 메타데이터 — omp-setup / omp-orchestrator 만 write, 그 외 read-only. kernel vmlinux 경로 / qemu cmd 등 (D7) |

### Environment (envsetup T04가 채움)

| 필드 | 설명 |
|---|---|
| `libc_version` | `"2.35"` / `"static"` / `"unknown"` |
| `libc_path` | 추출된 libc 절대경로 (host path) |
| `ld_path` | 추출된 ld 절대경로 (host path) |
| `docker_image` | 빌드된 이미지 태그 (예: `omp-42bee218`) |
| `mitigations` | `{ nx, pie, canary, relro, seccomp, raw }` |
| `remote` | `{ host, port, wrapper, command }` (Dockerfile에서 추론) |

### Workspace path derive (envsetup 재설계)

별도 `pwno-mcp_paths` field 는 더 이상 박지 않는다 (T11/T12 폐지). 대신
**derive 룰** — Orchestrator + SA + Exploiter 모두 동일하게 계산:

```
workspace_id      = "omp-" + basename(state.challenge_dir) + "-" +
                    state.binary_input_sha256.slice(0, 8)
host workspace    = state.workspace_root + "/" + workspace_id
container path    = "/workspace/" + workspace_id
container binary  = container path + "/" + basename(state.binary_path)
container libc    = container path + "/" + basename(state.libc_path)
container ld      = container path + "/" + basename(state.ld_path)
```

omp-setup agent (Phase 5) 가 `.omp/artifacts/` 의 patched binary + 모든
extracted lib 를 `state.workspace_root + "/" + workspace_id` 로 stage 한다.
호스트 backing dir 은 `<plugin-root>/workspace/<workspace_id>/`. challenge
별 mount path 변경 없이 같은 컨테이너가 challenge 들을 subdir 로 격리.

Multi-NEEDED 챌린지 (libm/libz/libbz2/liblzma 등) 의 추가 라이브러리는
`state.extracted_libs` map 으로 SONAME → host path 보존. container 경로는
같은 derive 룰 (basename forward) 로 계산.

### Reverser (T07)

| 필드 | 설명 |
|---|---|
| `reverser_summary_path` | `reverser-analysis.md` 절대경로 (구조화 artifact) |
| `reverser_research_path` | `reverser-research.md` 절대경로 (영문 narrative) |
| `reverser_research_ko_path` | `reverser-research.ko.md` 절대경로 (한국어 narrative) |
| `reverser_analyzed_at` | ISO timestamp |

### Downstream fields (3-agent exploit pipeline)

> Exploit pipeline redesign (2026-04-17) 반영.
> Spec: `.omc/specs/deep-interview-exploit-pipeline.md`

**VulnHunter output (T10) — Summary/Detail split (state-split-vuln-candidates.md D2):**

`vuln_candidates[]` 는 `state.db` 의 *summary row* 로 박힘. detail 은 별개
`candidates` detail array (FK). 두 영역 합성은 `mcp__omp-db__read_candidate`
또는 `VulnCandidateSchema = VulnCandidateSummary.merge(VulnCandidateDetail)`.
(옛 `.omp/candidates/<id>.json` per-file 폐기 — database-mcp cutover.)

*Summary fields* (state.db summary row):

| 필드 | 설명 |
|---|---|
| `id` | Candidate 식별자 (e.g. `vuln_4` / `derived_vuln_4_vuln_16`). alphanumeric + `_` + `-` 만 허용. |
| `primitive` | Exploitation primitive tag (e.g. `stack_bof`, `tcache_poison`). |
| `verification_result` | "confirmed" / "failed" / "inconclusive" / undefined. Presence IS the verification flag. |
| `agent` | Producing sub-agent (e.g. `VH-3` / `SA-04`). Trace of provenance. |
| `combined_from` | Derived candidate 의 source ids. |
| `description` | 2-3 줄 short claim of *what* (≤400 chars). 무엇이냐만 — 왜 는 `rationale` (detail). |
| `gives_count` / `needs_count` | detail 의 array length — *진행 정도* 만 노출. |
| `has_poc` | `detail.poc_script_path` 존재 여부 (boolean). |

*Detail fields* (state.db detail array):

| 필드 | 설명 |
|---|---|
| `location` | Function name / offset / source line. |
| `confidence` | 0.0–1.0 hunter confidence. |
| `rationale` | Why the hunter thinks this candidate is viable (full reasoning). |
| `libc_range` | Required libc range (e.g. `"2.31-2.35"`). |
| `origin_type` | How this candidate was discovered (`initial` / `combine` / `incidental` / …). |
| `derived_from` | Derived/incidental candidate 의 trigger candidate id. |
| `poc_script_path` | PoC script 절대경로 — verified primitive 의 지식 단위. COMBINE SA 가 source 로 read. |
| `gives` | This primitive provides (e.g. `["libc_base", "rip_control"]`). |
| `needs` | This primitive requires (e.g. `["canary"]`). |
| `verification_blockers` | SA verify 가 보고한 tool/method 영역 blocker (`cause` / `suggested_fix` / `retry_recommended`). 다음 SA spawn 시 auto-forward. |

**기타 VulnHunter meta:**

| 필드 | 설명 |
|---|---|
| `vulnhunter_analysis_path` | `vulnhunter-analysis.md` 절대경로 |
| `vulnhunter_analyzed_at` | ISO timestamp |

> **Schema enforcement:** `patch_state` 의 `vuln_candidates[]` 는 summary
> field 만 수락 — detail field 박힘 시 `vuln_candidates_detail_in_summary_patch`
> reject (database.md). DB cutover 는 fresh start (옛 file format migration
> 없음, T3 폐기) 라 old-format 로드 분기 자체가 소멸.

**StrategyAgent plan (T14):**

| 필드 | 설명 |
|---|---|
| `strategist_plan_path` | `strategist-plan.md` 절대경로 |
| `strategist_planned_at` | ISO timestamp |

**Exploit steps + execution (T14~T16):**

| 필드 | 설명 |
|---|---|
| `stages` | StrategyAgent가 설계한 exploit step plan. 각 항목: id, status, attempts, timestamps |
| `stages[].goal` | **(확장)** 이 step이 증명할 것 (e.g., "ret address를 0xdeadbeef로 제어") |
| `stages[].expected_result` | **(확장)** 성공 시 관찰 기대값 (e.g., "rip == 0xdeadbeef") |
| `stages[].candidate_id` | **(확장)** 대응하는 vuln_candidates[].id |
| `current_stage_index` | 현재 진행 중 stage |
| `current_exploit_script` | Exploiter가 이터레이트 중인 pwntools 경로 |

**Exploitation 중 수집된 데이터:**

| 필드 | 설명 |
|---|---|
| `leaks` | Leak ledger — exploitation 중 확보한 주소 (name, value, stage, discovered_at). **주의: ASLR으로 실행마다 달라지므로 재실행에 재사용 금지. Human-readable 참고용.** |
| `corrections` | User correction audit log (T20) |

> **PoC code as knowledge transfer (parallel model):** Leak 값(libc_base,
> canary 등)은 ASLR로 실행마다 달라져서 state에 저장해도 재사용 불가.
> 대신 `poc_script_path`가 지식 단위 — leak을 획득하는 코드가 다음 라운드
> SA에게 전달된다. COMBINE SA는 source PoC scripts를 파일로 읽어 leak
> 획득 로직을 단일 `io = process()` 연결에 합성한다.

**stage_map.yaml은 폐지됨.** Stages는 StrategyAgent가 동적으로 생성.
`autonomous_stage_rate`는 StrategyAgent 생성 stages 기준으로 계산.

### Meta

| 필드 | 설명 |
|---|---|
| `created_at` | ISO timestamp |
| `updated_at` | 매 save 시 자동 갱신 |

### Atomic write (DB transaction)

`mcp__omp-db__patch_state` handler 는:
1. 기존 row 로드 + shallow merge 후 Zod schema 재검증 (invalid면 reject, row 무변경)
2. `updated_at` 자동 갱신
3. multi-table write 를 한 SQLite transaction (bun:sqlite + WAL) 으로 — 부분 쓰기 없음

(옛 file 시절 `saveChallengeState` 의 `state.json.tmp` + `rename` 원자성은
DB transaction 으로 대체 — `saveChallengeState` 함수는 T22 에서 제거.)

---

## `journal.md` — append-only progress log

Format은 자유로운 markdown. 각 항목은 H2 heading으로 구분:

```markdown
# oh-my-pwn Handoff Journal

_Challenge dir: /abs/path/to/challenge_
_Created: 2026-04-15T05:54:30.371Z_

> This file is an **append-only progress log** written by OmP agents.
> It is **read-only for humans** — corrections flow through the prompt
> channel and are applied by the Orchestrator to state.db plus a
> `## User correction` block below. Do not edit this file by hand.

## Inputs

- binary: `/abs/path/prob`
- Dockerfile: `/abs/path/Dockerfile`
- source present: false

## challenge loaded — 2026-04-15T05:54:30.371Z

- binary sha256: `3a55dc...`
- ...

## envsetup — 2026-04-15T05:54:46.256Z

### Mitigations
- raw: `NX=on PIE=on Canary=on RELRO=full`
- ...

## Reverser analysis complete — 2026-04-15T06:01:00.239Z

- Binary: /abs/path/prob
- Functions in analysis set: 7
- ...

## User correction — 2026-04-15T07:10:00.000Z

> libc 버전은 2.31이야, docker image 태그가 잘못된 것 같아

- Updated state.libc_version: "2.35" → "2.31"
- Re-running envsetup to regenerate docker image
```

### Write rules

- **Agent는 `appendJournalSection(heading, body)` 경유만.** 헤더는 자동
  timestamp. Body는 markdown.
- **User correction 블록도 agent가 씀.** 사용자가 prompt로 "libc 버전은
  2.31이야"라고 말하면 orchestrator가:
  1. `mcp__omp-db__patch_state`로 `state.libc_version` 수정
  2. `omp_append_journal("User correction", "> <사용자 원문>\n\n- Updated ...")`
  3. 필요하면 해당 단계부터 재계획

---

## Artifacts 디렉토리

### libc / ld

Envsetup이 docker image에서 `docker cp`로 추출:

```
artifacts/libc.so.6
artifacts/ld-linux-x86-64.so.2
```

Patchelf로 binary의 interpreter와 rpath를 이 경로로 rewrite하므로, 로컬
pwntools나 gdb가 **docker image의 libc를 정확히** 로드할 수 있음.

### Binary 백업 (prob.orig)

Patchelf가 원본 binary를 덮어쓰기 전에 `<name>.orig`로 백업. 재실행 시
`binary_path`가 이미 patched 상태면 백업을 복원한 뒤 재패치 → 결정적
(deterministic) 동작.

### Reverser 산출물 (3개 artifact + 2개 pseudocode 디렉터리)

#### reverser-analysis.md (구조화 reference)

VulnHunter의 주 입력. 다음 섹션 포함:

- Program Overview (1 문단 + 5-8 bullet neutral observations)
- Key Observations
- Entry Points & Analysis Roots 표
- Types introduced by Reverser (Arrays / Pointers / Primitives / Structs)
- Function Map 표 (Address / Renamed / Original / 1-line purpose)
- Functions (detailed):
  - 함수별 Purpose paragraph
  - Stack frame 서브섹션 — canary, saved_rbp, return_address 위치 + 거리 계산
  - Pseudocode 파일 링크 (`pseudocode/<name>.txt`)
  - Key annotations (@ 0xADDR: ... 포맷)
- Imports / Exports / Interesting strings (flat lists, no severity)

#### pseudocode/ (HLIL — agent용)

분석한 함수별 HLIL 디컴파일 결과. `decompile_to_file`로 개별 저장.
intrinsic (`sbb.q`, `cmov` 등)과 named parameter를 보존하므로 VulnHunter가
flag-dependent 조건부 allocation 등 exploit-critical 패턴을 직접 확인 가능.

#### pseudocode-c/ (Pseudo C — 사람용)

같은 함수들의 Pseudo C 렌더링. C 문법에 가까워 사람이 읽기 편하지만
`sbb` 같은 intrinsic이 `x - x`로 소실될 수 있음. agent는 참조하지 않음.

#### reverser-research.md (영문 narrative)

사람이 top-to-bottom 읽는 "연구자 findings memo":

- Executive summary (1-2 문단)
- Analysis approach
- What each function does (prose)
- Types I applied
- Data entry points
- Stack frames of interest
- Handoff notes

#### reverser-research.ko.md (한국어 narrative)

Full translation. Technical terms (read, printf, stack, rbp, canary,
RELRO, ...)은 영문 유지. Heading convention: `## Executive summary (요약)`.

---

## logs/ 디렉토리

### docker-build-*.log

`envsetup`이 `docker build`를 실행할 때마다 stdout+stderr를 전부
timestamped 파일로 저장. 빌드 실패 시 사용자가 이 로그를 직접 읽어서
원인 파악 가능. Error 객체의 `buildLogPath` 필드로 경로 제공.

### 기타 로그 (future)

- exploit 실행 로그
- verifier 판정 로그
- gdb 세션 기록

---

## Idempotency & 재실행

재실행 시 각 단계가 중복 작업을 어떻게 피하는지:

### Challenge load (`omp_load_challenge`) — init-or-verify

- `.omp/` 이미 존재 → 디렉토리 검증 + 누락 서브디렉토리만 생성 (`initializeOmpDir`
  idempotent). **state (DB) 시드는 안 함 (T20)** — state 는 db-mcp
  `lookup_challenge` 로 회수.
- `freshlyInitialized` = `.omp/journal.md` 부재 여부 (첫 로드 판정).
- **binary sha drift 감지는 폐지 (D4).** loader 는 sha 계산 / input-identity drift
  추적을 더 이상 하지 않음 — binary 식별 + sha 는 omp-setup Phase 0 (Detect) 책임
  (contract-load-detect-split D1/D2). 재시딩이 필요하면 `rm -rf .omp/` 후 reload 가 정본.

### Envsetup (omp-setup agent + atomic tool) — docker layer cache 위임

- 옛 `runEnvSetup` 단일 함수는 폐지 (T19). omp-setup agent 가 Phase 1-6 을 atomic
  tool (`omp_setup_docker_build` / `extract_file` / `patch_elf` / `verify_runtime`)
  로 순차 실행하며, 각 phase 결과를 `mcp__omp-db__patch_state` 로 partial commit
  (중간 실패해도 진행한 만큼 DB 에 반영).
- docker build cache: **우리 자체 cache 로직 (canReuse / mtime 비교) 없음 (T20)** —
  docker 의 layer cache 에 위임. `force_rebuild: true` → `--no-cache`.
- `omp_setup_docker_build` 는 `image_tag_hint` 필수 (옛 sha-derived fallback 폐지).

### Reverser (omp-reverser agent) — summary cache skip + force

- `state.reverser_summary_path` 존재 + 파일 실재 + delegation prompt 에 `force: true`
  미전달 → journal 에 skip entry append 후 stop (재분석 안 함).
- `force: true` 전달 시 강제 재실행. BN mutation 은 idempotent (이미 renamed 함수
  재rename = 덮어쓰기, `.bndb` 에 저장).
- **binary sha match 체크는 없음** — 파일 존재 + force 플래그만으로 판단. 옛
  `omp_run_reverser` tool 은 폐기 (omp-orchestrator 가 `omp_task_launch` 로 spawn 하는 agent).

---

## 상태 mutation 원칙 — 누가 무엇을 쓸 수 있는가

| 주체 | 쓸 수 있는 것 | 금지 |
|---|---|---|
| **library** (loader, envsetup) | `journal.md` (`appendJournalSection`), `artifacts/*`, `.omp/` 디렉토리 init (`initializeOmpDir`) | state/candidate 직접 write (DB 로 이전 — `saveChallengeState`/`saveCandidate` T22 제거), 사용자 입력 직접 읽기 |
| **agent (Orchestrator)** | `mcp__omp-db__patch_state` / `omp_append_journal` / `mcp__omp-db__{create,patch,delete}_candidate` (+ challenge identity tool) 경유. **병렬 환경의 sole writer** | `write` / `edit` tool로 DB / journal.md 직접 수정 |
| **agent (omp-setup)** | `mcp__omp-db__patch_state` (+ `register_challenge`) / `omp_append_journal` 경유 (Phase 0-6 순차) — `etc` write 허용 | candidate write 미사용 (omp-setup 영역 아님). |
| **agent (Reverser)** | `mcp__omp-db__patch_state` (path / timestamp 만) / `omp_append_journal` 경유 + `write` tool로 `artifacts/reverser-*.md` 생성 | `etc` write / candidate write |
| **sub-agent (VulnHunter / Strategist / Exploiter)** | `mcp__omp-db__read_state` / `read_candidate` 로 read 만. 결과는 task return value 로 반환. | `mcp__omp-db__patch_state` / `{create,patch,delete}_candidate` 다 **ACL 2 layer deny** (sole writer 위반). `etc` write 도 deny. |
| **사용자** | prompt 채널로 agent에게 correction 지시 | DB / 파일 직접 수정 |
| **`mcp__omp-db__patch_state`** | state 부분 필드 (Zod validated, `agent_id` ACL). `vuln_candidates[]` 는 summary field 만 (detail 박힘 시 reject) | identity/version 키 (`challenge_id` / `schema_version`) |
| **`mcp__omp-db__{create,patch,delete}_candidate`** | `vuln_candidates[]` summary row + detail array (한 tx) | Orchestrator 외 sub-agent (ACL) |

**protected fields:** `mcp__omp-db__patch_state`는 `challenge_id` /
`schema_version` 같은 identity/version 키를 patch 대상에서 제외. 그 외 필드는
patchable — omp-setup Phase 3 이 patchelf 결과를 `binary_path` 박음
(`binary_sha256` 같이).

**`vuln_candidates` channel split (state-split-vuln-candidates.md D2/D3):**

| 데이터 | 채널 |
|---|---|
| Summary fields (id / verification_result / primitive / agent / combined_from / description / gives_count / needs_count / has_poc) | `mcp__omp-db__patch_state({vuln_candidates: [{...}]})` 가능 — summary-only |
| Detail fields (rationale / verification_blockers / gives / needs / poc_script_path / location / libc_range / origin_type / derived_from / confidence) | `mcp__omp-db__patch_candidate({id, patch: {detail}})` — `patch_state` 에 박힘 시 reject |
| Summary + Detail 동시 갱신 | `mcp__omp-db__patch_candidate({id, patch: {summary, detail}})` 한 호출 (summary row + detail array 한 tx) |
| 신규 candidate | `mcp__omp-db__create_candidate({candidate: {summary + detail}})` (한 tx) |
| Candidate 폐기 | `mcp__omp-db__delete_candidate({id})` (row + detail array cascade) |

ACL enforcement: `src/orchestration/agent-tool-restrictions.ts`. sub-agent
가 candidate write tool 호출하면 tool 실행 전 reject.

---

## Human intervention protocol (prompt-driven correction)

사람이 agent의 판단에 이의를 제기하는 방법:

### 1. Journal을 읽음

```bash
cat <challenge-dir>/.omp/journal.md
```

사람이 가장 먼저 보는 것. agent가 현재 어디까지 왔는지, 어떤 판단을
내렸는지, 어디서 막혔는지 narrative 형태로 파악.

### 2. Agent와의 대화 (prompt 채널)

TUI에 직접 입력:

```
libc 버전은 2.35가 아니고 2.31이야. Dockerfile에서 ubuntu:20.04를
기반으로 하는데 glibc 2.31이어야 해. docker image 재빌드해줘.
```

### 3. Orchestrator 응답

```
알겠습니다. state.libc_version을 "2.31"로 수정하고 envsetup을 재실행
합니다.

1. mcp__omp-db__patch_state: libc_version="2.31" 기록
2. omp_append_journal("User correction", ...)
3. user prompt 에 "setup 재설정" 박아서 force re-setup → Orchestrator
   Phase 0 gate 가 omp-setup agent 를 force_rebuild=true 로 재실행
4. 완료 후 reverser 단계로 진행
```

### 4. Journal에 기록됨

```markdown
## User correction — 2026-04-15T07:10:00.000Z

> libc 버전은 2.35가 아니고 2.31이야. Dockerfile에서 ubuntu:20.04를
> 기반으로 하는데 glibc 2.31이어야 해. docker image 재빌드해줘.

- Updated state.libc_version: "2.35" → "2.31"
- Re-running envsetup with force:true
```

### 중요한 것

- **사용자는 journal을 수정하지 않음.** agent가 append.
- **사용자는 state(`state.db`)를 직접 수정하지 않음.** agent가 `mcp__omp-db__patch_state`로
  수정.
- **사용자 원문은 quote block으로 보존됨.** 나중에 무엇을 왜 바꿨는지
  audit할 수 있도록.

이 프로토콜은 `.omc/specs/deep-interview-oh-my-pwn.md`의 Round 4
contrarian 해결과 Round 2 refinement에서 locked됨.

---

## Source-present mode

`state.source_present === true`인 경우:

- Reverser는 **early exit** — BN MCP를 사용하지 않고 3개 stub artifact 생성:
  - `reverser-analysis.md` (source file 목록만)
  - `reverser-research.md` (source-present 설명)
  - `reverser-research.ko.md` (한국어 버전)
- VulnHunter (T10)는 `state.source_paths`의 파일들을 직접 읽음
- 이유: C source에 이미 의미 있는 이름/주석/타입이 있어서 Reverser 작업이
  redundant. 노력 낭비 방지.

---

## 관련 파일 요약

| 파일 | 역할 |
|---|---|
| `src/state/challenge-state.ts` | Zod schema 정의 (`ChallengeState`) — DB mapper 가 이 schema 로 row 재조립 |
| `src/state/io.ts` | `initializeOmpDir` / `getStatePaths` (state/candidate file IO 는 T22 제거) |
| `src/state/journal.ts` | `appendJournalSection`, `initializeJournal`, `appendUserCorrection` |
| `src/state/layout.ts` | 경로 헬퍼 (`resolveOmpDir`, `resolveArtifactsDir`, 등) |
| `src/state/constants.ts` | `.omp`, `journal.md`, schema version |
| `src/db/` | Drizzle schema (10 table) + migration runner + `openDb` (bun:sqlite, WAL). `state.db` |
| `src/db-mcp/` | DB MCP server `omp-db` — `server.ts` (11 tool) + `mapper.ts` (table↔nested) + `acl.ts` (Layer 2) |
| `src/loader/load-challenge-folder.ts` | challenge 폴더 validate + `.omp/` initialize (non-DB, T20) |
| `src/envsetup/` | docker build + libc 추출 + patchelf — omp-setup atomic tool 이 wrap |

다음 문서에서 **agent가 사용하는 tool 목록**을 다룹니다 → [tools.md](tools.md).
