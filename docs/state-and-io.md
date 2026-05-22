# State & I/O — `.omp/` 레이아웃과 데이터 흐름

이 문서는 OmP가 **어떻게 상태를 저장하고**, **어떤 산출물을 만들고**, 사람이
**어디를 읽고 어떻게 개입**하는지 정리합니다.

---

## 핵심 원칙

1. **각 challenge 폴더 안에 `.omp/` 디렉토리가 생기고, 모든 상태가 거기에
   저장됩니다.** 전역 `.omp/<slug>/` 같은 건 없음. Challenge 폴더를 tar로
   말아 다른 머신에 옮기면 OmP 상태도 같이 따라감.
2. **`state.json`은 machine-truth, `journal.md`는 human-readable.**
   State는 Zod-validated JSON, journal은 append-only markdown.
3. **사람은 journal만 읽음. 수정은 prompt 채널로만.** `vim journal.md`
   같은 파일 직접 편집은 지원하지 않음. 사용자가 correction을 prompt로
   말하면 orchestrator가 `state.json`을 고치고 `journal.md`에 correction
   블록을 append.
4. **Agent는 state file을 직접 쓰지 않음.** 반드시 `omp_read_state` /
   `omp_patch_state` / `omp_append_journal` tool 경유.
5. **병렬 환경에서 Orchestrator가 sole writer.** 병렬 실행되는
   StrategyAgent/Exploiter는 `omp_patch_state`를 호출하지 않고 결과만
   반환. Orchestrator가 수집 후 순차적으로 state에 반영. 동시 쓰기
   충돌 방지. (`omp_read_state`로 읽기는 가능.)

---

## `<challenge-dir>/.omp/` 레이아웃

```
<challenge-dir>/
├── prob                          ← binary (원본 또는 patchelf로 교체된 버전)
├── Dockerfile                    ← remote 재현용
├── chal.c                        ← (선택) C 소스 — 있으면 Reverser skip
└── .omp/                         ← OmP 상태 + 산출물
    ├── state.json                ← machine-truth. Zod schema (ChallengeState)
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

각 서브디렉토리는 T02 `initializeOmpDir`가 load 시 자동으로 생성합니다.

---

## `state.json` 스키마 (ChallengeState)

`src/state/challenge-state.ts`의 Zod schema가 single source of truth.
주요 필드를 그룹별로:

### Identification (loader T03가 채움)

| 필드 | 타입 | 설명 |
|---|---|---|
| `schema_version` | `"1"` | 스키마 버전 상수 |
| `challenge_dir` | string | challenge 폴더 절대경로 |
| `binary_path` | string | binary 절대경로 (원본 또는 patched) |
| `binary_sha256` | string | 현재 활성 binary의 sha (원본 또는 patched) |
| `binary_original_path` | string? | patchelf 백업 경로 `<.omp/artifacts/<name>.orig>` |
| `binary_original_sha256` | string? | patch 전 sha — input contract identity 보존용 |
| `binary_patched` | boolean? | patchelf가 이 run 또는 이전 run에서 적용됐는지 |
| `dockerfile_path` | string | Dockerfile 절대경로 |
| `source_present` | boolean | C 소스 존재 여부 |
| `source_paths` | string[] | 발견된 소스 파일 경로들 |

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

**VulnHunter output (T10):**

| 필드 | 설명 |
|---|---|
| `vuln_candidates` | Candidate 배열. 각 항목: id, primitive, location, confidence, rationale, libc_range |
| `vuln_candidates[].verified` | Exploiter가 검증 완료 여부 (boolean) |
| `vuln_candidates[].verification_result` | "confirmed" / "disproved" / "inconclusive" |
| `vuln_candidates[].poc_script_path` | **(parallel model)** verified primitive를 증명하는 PoC script 절대경로. Orchestrator가 COMBINE SA에게 지식 전달에 사용. |
| `vuln_candidates[].gives` | **(parallel model)** 이 primitive가 제공하는 것 (예: `["libc_base", "rip_control"]`). COMBINE 가능성 판단에 사용. |
| `vuln_candidates[].needs` | **(parallel model)** 이 primitive가 전제하는 것 (예: `["canary"]`). COMBINE 순서 결정에 사용. |
| `vuln_candidates[].combined_from` | **(parallel model)** COMBINE으로 생성된 경우 원본 candidate ID 목록. |
| `vulnhunter_analysis_path` | `vulnhunter-analysis.md` 절대경로 |
| `vulnhunter_analyzed_at` | ISO timestamp |

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

### Atomic write

`saveChallengeState`는:
1. Zod schema로 재검증 (invalid면 throw)
2. `updated_at` 자동 갱신
3. `state.json.tmp`에 쓴 뒤 `rename`으로 원자적 교체 (부분 쓰기 없음)

---

## `journal.md` — append-only progress log

Format은 자유로운 markdown. 각 항목은 H2 heading으로 구분:

```markdown
# oh-my-pwn Handoff Journal

_Challenge dir: /abs/path/to/challenge_
_Created: 2026-04-15T05:54:30.371Z_

> This file is an **append-only progress log** written by OmP agents.
> It is **read-only for humans** — corrections flow through the prompt
> channel and are applied by the Orchestrator to state.json plus a
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
  1. `omp_patch_state`로 `state.libc_version` 수정
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

모든 loader / envsetup / reverser는 **cache 체크**를 거친 뒤 실행됩니다:

### `loadChallengeFolder` (T03) — load-or-init

- `state.json` 이미 존재 → 그대로 로드
- `binary_sha256` 재계산 → drift 감지하면 **state는 건드리지 않고 journal에만
  `## binary sha drift` 블록 append**. 재시딩은 사용자가 명시적으로 `rm -rf .omp/`
  하거나 prompt correction으로 지시해야 함.
- 원칙: 사용자 동의 없이 agent가 state를 mutation하지 않음.

### `runEnvSetup` (T04) — partial commit

- 파이프라인 각 단계 후 `saveChallengeState` 호출 → 중간 실패해도 진행한
  만큼 commit됨
- `docker image inspect`로 cache hit이면 build skip, 그 외엔 rebuild

### `omp_run_reverser` (agent 호출) — sha match skip + force

- `state.reverser_summary_path` 존재 + binary sha match → skip 후 cached
  summary 반환
- 사용자가 `force: true` 넘기면 강제 재실행. BN mutation은 idempotent
  (이미 renamed 함수에 대한 rename은 덮어쓰기). BN은 `.bndb` database에 변경사항 저장.

---

## 상태 mutation 원칙 — 누가 무엇을 쓸 수 있는가

| 주체 | 쓸 수 있는 것 | 금지 |
|---|---|---|
| **library** (loader, envsetup) | `state.json` (`saveChallengeState`), `journal.md` (`appendJournalSection`), `artifacts/*` | 직접 사용자 입력 읽기 |
| **agent (Orchestrator)** | `omp_patch_state` / `omp_append_journal` tool 경유. **병렬 환경의 sole writer** | `write` / `edit` tool로 state.json / journal.md 직접 수정 |
| **agent (Reverser, VulnHunter)** | `omp_patch_state` / `omp_append_journal` tool 경유 (순차 실행 시) | state.json 직접 쓰기 |
| **agent (SA, Exploiter — 병렬)** | `omp_read_state`로 읽기만. 결과는 session 출력으로 반환 | `omp_patch_state` / `omp_append_journal` 호출 금지 (sole writer 위반) |
| **agent (Reverser)** | `write` tool로 `artifacts/reverser-*.md` 생성 | `state.json` / `journal.md` 직접 쓰기 |
| **사용자** | prompt 채널로 agent에게 correction 지시 | 파일 직접 수정 |
| **`omp_patch_state`** | `state.json` 부분 필드 (Zod validated) | `challenge_dir` / `schema_version` / `binary_path` — 핵심 identity |

**protected fields:** `omp_patch_state`는 patch 객체에서 `challenge_dir`,
`schema_version`, `binary_path` 를 자동으로 제거합니다. 이 세 필드는 loader
초기 시점 외에는 변경 금지 (`binary_path`는 patchelf가 `binary_patched`
flag와 `binary_original_path` 관리로 handle).

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

1. omp_patch_state: libc_version="2.31" 기록
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
- **사용자는 state.json을 수정하지 않음.** agent가 `omp_patch_state`로
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
| `src/state/challenge-state.ts` | Zod schema 정의 (`ChallengeState`) |
| `src/state/io.ts` | `loadChallengeState`, `saveChallengeState`, `initializeOmpDir` |
| `src/state/journal.ts` | `appendJournalSection`, `initializeJournal`, `appendUserCorrection` |
| `src/state/layout.ts` | 경로 헬퍼 (`resolveOmpDir`, `resolveArtifactsDir`, 등) |
| `src/state/constants.ts` | `.omp`, `state.json`, `journal.md`, schema version |
| `src/loader/load-challenge-folder.ts` | T03 — challenge 폴더 validate + initialize |
| `src/envsetup/run-envsetup.ts` | T04 — docker build + libc 추출 + patchelf 파이프라인 |

다음 문서에서 **agent가 사용하는 tool 목록**을 다룹니다 → [tools.md](tools.md).
