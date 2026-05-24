# Agents — OmP의 에이전트 설계

이 문서는 OmP의 agent가 **어떻게 정의되고 등록되는지**, 각 agent의
**역할과 현재 상태**, 그리고 **프롬프트 구성 원칙**을 정리합니다.

---

## Agent factory 패턴

모든 OmP agent는 동일한 factory 패턴으로 정의됩니다:

```ts
// src/agents/types.ts
export type AgentConfig = {
  description: string
  prompt: string
  model: string
  mode: "primary" | "subagent" | "all"
}

export type AgentFactory = (model: string) => AgentConfig
```

각 agent 파일은 `create<AgentName>Agent(model)` 함수를 export합니다:

```ts
// src/agents/omp-orchestrator.ts
const ORCHESTRATOR_PROMPT = `...system prompt...`

export function createOmpOrchestratorAgent(model: string): AgentConfig {
  return {
    description: "CTF pwnable auto-solve orchestrator. ...",
    prompt: ORCHESTRATOR_PROMPT,
    model,
    mode: "all",
  }
}
```

**Factory 패턴인 이유:**
- Model을 런타임 주입 가능 → 같은 agent를 GPT-5.4 / Opus 4.6 / Gemini 3
  Pro 중 어디서든 돌릴 수 있음
- Prompt가 plain string 상수라 테스트 가능 (`expect(agent.prompt).toContain(...)`)
- OmO의 factory 패턴과 호환 (미래에 OmO 인프라를 부분 재활용할 여지)

---

## Agent registry

`src/agents/definitions.ts`에서 모든 agent의 `ompAgentConfigs` map을
정의합니다:

```ts
const DEFAULT_MODEL = "openai/gpt-5.5"

export const ompAgentConfigs: Record<string, AgentConfig> = {
  "omp-orchestrator": createOmpOrchestratorAgent(DEFAULT_MODEL),
  "omp-reverser": createOmpReverserAgent(DEFAULT_MODEL),
  // 추�� 추가 (3-agent exploit pipeline):
  // "omp-vulnhunter": createOmpVulnhunterAgent(DEFAULT_MODEL),
  // "omp-strategist": createOmpStrategistAgent(DEFAULT_MODEL),
  // "omp-exploiter": createOmpExploiterAgent(DEFAULT_MODEL),
}
```

이 map은 `plugin.ts`의 `config` hook에서 `Object.assign(cfg.agent, ompAgentConfigs)`로
opencode config에 주입됩니다. 결과적으로 opencode TUI agent picker에
`omp-orchestrator`, `omp-reverser`가 나타납니다.

### 기본 모델

현재 기본값은 `openai/gpt-5.5`. 이유:
- OmP는 JSON 스키마 정확도가 중요 (state patch, BN MCP 호출 등) — GPT-5
  계열은 structured output에 강함
- Claude Opus는 창의적 판단에 좋지만 script/tool 호출 정밀도는 GPT가 비등
- 사용자가 TUI에서 per-session model 변경 가능하므로 기본값은 "안정적"인
  것으로 선정

향후 per-model prompt variant (`default.ts` / `gpt.ts` / `gemini.ts`)를
도입하면 agent factory가 model에 따라 다른 prompt 버전을 반환할 수 있게
확장 예정 (OmO 패턴). 현재는 단일 variant.

---

## Agent mode

`AgentConfig.mode`는 opencode TUI가 agent를 어떻게 보여줄지 결정합니다:

| mode | 의미 |
|---|---|
| `primary` | 사용자가 agent picker에서 직접 선택할 수 있는 top-level agent |
| `subagent` | 다른 agent가 delegation으로만 호출하는 내부 agent |
| `all` | 양쪽 다 가능 (디버깅용) |

**현재 상태 (2026-04-17):**
- `omp-orchestrator`: `mode: "all"`
- `omp-reverser`: `mode: "all"`
- `omp-vulnhunter`: `mode: "all"` (T10)
- `omp-strategist`: `mode: "all"` (T14)
- `omp-exploiter`: `mode: "all"` (T16)

**향후 운영 모드:**
- `omp-orchestrator` → `primary` (사용자 진입점)
- `omp-reverser` → `subagent` (orchestrator가 delegate)
- 나머지 future agents도 `subagent`

디버깅 단계에서는 양쪽 agent 전부 사용자가 직접 띄울 수 있게 `"all"`로
둡니다. 운영 전환 시점에 `definitions.ts`에서 mode만 바꾸면 됨.

---

## 현재 agent 목록

### omp-orchestrator

**역할:** CTF pwn 파이프라인의 총괄 지휘자. 사용자에게서 challenge 폴더
경로를 받아 `Load → EnvSetup → Reverse → VulnHunt → Exploit → Verify`
순서로 sub-agent / tool을 호출하고, 각 단계 결과를 state에 반영, 사용자
correction을 받아 state를 고치고 재계획.

**병렬 실행 단계별 역할 (새 설계):**
- **Phase 1:** VH ensemble을 병렬로 spawn (각 VH가 독립 관점으로 분석) → 모든 VH 완료 후 결과 merge/dedup → candidate list 확정
- **Phase 2:** candidate별로 SA+Exploiter 쌍을 병렬로 spawn (SA가 Exploiter를 sub-agent로 spawn) → 각 쌍이 독립 실행
- **Phase 3:** 모든 결과 수집 → `omp_patch_state` 호출 (sole writer). 성공 candidate 있으면 파생 primitive 탐색용 VH 2차 분석 가능. Exploiter의 부수 발견(새 leak/heap primitive) → 새 candidate로 등록 후 Phase 2 재진입
- **Phase 4:** flag/shell 획득 → SUCCESS. 전체 소진 + cascading 없음 → 사용자 handoff. Budget 초과 → 사용자 handoff.

> **인프라 노트:** 병렬 spawn은 OmO의 `task` tool + BackgroundManager + ConcurrencyManager 인프라 포팅 필요. 현재 미구현. 세부 사항은 아래 "병렬 실행 인프라" 섹션 참조.

**현재 구현 상태 (2026-05):**
- ✅ 파이프라인 skeleton 프롬프트
- ✅ Phase 0 setup gate — `omp_load_challenge` (fresh init) + omp-setup agent launch (env build + extract + patchelf + verify + stage)
- ✅ Phase 1 Reverse — `omp-reverser` delegation
- ✅ Phase 1-3 병렬 VH ensemble / SA race / Exploiter cascading (parallel orchestration spec)

**Tool 사용:**
- `omp_load_challenge` (fresh challenge 첫 호출)
- `omp_read_state` (매 phase 시작)
- `omp_patch_state` (Phase 1+ 결과 기록 — sole writer. Phase 0 setup 동안에는 omp-setup agent 가 직접 쓰는 D1 relaxation)
- `omp_append_journal` (user correction 기록 외)
- `omp_task_launch` / `_wait_all` / `_wait_any` / `_cancel` (sub-agent 인프라)

**파일:** `src/agents/omp-orchestrator.ts`

### omp-reverser

**역할:** Challenge binary의 **semantic program understanding**을 생성.
BN MCP를 통해 함수/변수 rename, inline comment 주입, 타입 refinement
(array / pointer / struct / primitive)를 적용해서 BN DB에 반영하고,
3개의 산출물을 `<challenge-dir>/.omp/artifacts/`에 기록:

1. `reverser-analysis.md` — 구조화된 reference (function map, per-function
   렌더된 pseudocode + stack frame + key annotations)
2. `reverser-research.md` — 영문 narrative 연구 보고서
3. `reverser-research.ko.md` — 한국어 narrative (full translation, 기술용어
   영문 유지)

**Scope discipline (중요):** Reverser는 **취약점 판단을 하지 않음**.
"vulnerable", "BOF", "primitive" 같은 단어는 프롬프트 forbidden-words
리스트로 금지. 취약점 reasoning은 VulnHunter의 몫. 자세한 원칙은 아래
"프롬프트 구성 원칙" 섹션 참조.

**3-pass self-review (Option E):**
- **Pass A (mechanical):** 모든 `rename_function` / `rename_multi_variables`
  / `set_comment` 호출이 성공했는지, 모든 함수에 purpose paragraph가
  있는지, key annotation이 있는지 점검. LLM 호출 없음.
- **Pass B (semantic consistency):** 자기가 만든 artifact를 다시 읽고
  "purpose paragraph가 정말 pseudocode와 일치하는가?" 점검. 불일치 시
  tentative flag.
- **Pass C (full-context refinement):** 전체 프로그램 맥락을 알고 난 뒤
  각 함수를 재annotate. cross-function facts는 허용, cross-function
  judgments는 금지 (forbidden-words 규칙 유지).

**BN 사전 설정 요구사항:** Reverser는 Binary Ninja에서 BN MCP HTTP server가
port 9009에 실행 중이어야 동작. Step 0에서 `get_binary_status`가 실패하면
`load_binary`로 binary 파일을 로드한 뒤 진행. BN은 `.bndb` database를 자동
저장해서 사용자가 GUI에서 확인 가능.

**Tool 사용:**
- `omp_read_state`, `omp_patch_state`, `omp_append_journal`
- `omp_get_template` — research report 템플릿 로드
- `omp_verify_template_output` — 템플릿 작성물 구조 검증
- BN MCP tools: `get_binary_status`, `load_binary`, `list_methods`,
  `decompile_function` (기본 HLIL, `lang=pseudoc` 옵션), `decompile_to_file`,
  `rename_function`, `rename_multi_variables`, `retype_variable`, `set_comment`,
  `set_function_comment`, `set_function_prototype`, `define_types`,
  `declare_c_type`, `get_stack_frame_vars`, `get_callers`, `get_callees`,
  `save_bndb`, 등

**파일:** `src/agents/omp-reverser.ts` (프롬프트 ~800줄, 가장 복잡한 agent)

---

## Exploit pipeline agents (T10 ~ T17, 구현 완료)

> **Exploit pipeline redesign (2026-04-17).** Deep Interview 10라운드로 결정화.
> Spec: `.omc/specs/deep-interview-exploit-pipeline.md`

### Pipeline 구조

```
Orchestrator
  │
  ├─── Phase 1: VulnHunter Ensemble (병렬)
  │      ├─ VH-1 (관점 A) ──┐
  │      ├─ VH-2 (관점 B) ──┼→ Orchestrator merge/dedup → candidate list
  │      └─ VH-N (관점 N) ──┘
  │
  ├─── Phase 2: Iterative Rounds (반복 루프, state.json = blackboard)
  │      Round 1:
  │        ├─ SA-1 (VERIFY candidate A) → Exploiter-1 (session_id=1)
  │        ├─ SA-2 (VERIFY candidate B) → Exploiter-2 (session_id=2)
  │        └─ SA-3 (VERIFY candidate C) → Exploiter-3 (session_id=3)
  │               verified 결과 (poc_script_path, gives, needs) → blackboard
  │      Round N:
  │        └─ SA-N (COMBINE verified A+B) → Exploiter-N (session_id=N)
  │              source PoC scripts 합성 → single connection exploit
  │      * 임의 SA가 flag 획득 → 나머지 즉시 취소 (early-exit)
  │
  ├─── Phase 3: Result Collection + Cascading
  │      Orchestrator가 결과 수집 → state 기록 (sole writer)
  │      경로 A: verified candidate → VH 2차 분석 (파생 primitive)
  │      경로 B: Exploiter 부수 발견 → 새 candidate 등록
  │      → Phase 2 다음 Round로 재진입
  │
  └─── Phase 4: Termination
         Flag/shell 획득 → SUCCESS (early-exit 포함)
         전체 소진 + cascading 없음 → 사용자 handoff
         Budget 초과 → 사용자 handoff
```

**핵심 원칙:**
- **Incremental proof:** 각 step은 하나만 증명 (bof 존재 → ret offset → ROP → shell)
- **역할 분리 = 실패 귀인:** VulnHunter 틀림 = 잘못된 candidate, StrategyAgent 틀림 = 잘못된 plan, Exploiter 틀림 = 잘못된 script
- **Staged escalation:** Exploiter → SA → Orchestrator(cascading 재진입 or VulnHunter 2차) → user 단계적 복귀
- **Ensemble consensus:** VulnHunter는 ensemble 병렬로 분석, Orchestrator가 merge/dedup
- **Sole writer:** Orchestrator만 state를 쓰고 SA/Exploiter는 결과 반환만
- **Single container + session_id:** pwno-mcp 1개 container, Exploiter마다 다른 session_id로 격리
- **Shared blackboard:** state.json의 poc_script_path / gives / needs가 라운드 간 지식 이전 수단
- **PoC code as knowledge transfer:** Leak 값 저장 안 함 (ASLR). Leak 획득 코드를 합성.
- **Early-exit:** 임의 SA가 flag 획득 시 나머지 SA 즉시 취소

### omp-vulnhunter (T10) ✅

- **역할:** Reverser artifact를 읽고 vulnerability candidate 발견 + 랭킹.
  **Bug finder로서 exploit 전략 설계는 하지 않음** — 전략은 StrategyAgent의 몫.
- **Ensemble 모드:** Orchestrator가 여러 VH 인스턴스를 병렬로 spawn해서 독립적으로 분석. 각 VH는 **다른 VH의 결과를 참조하지 않음** — 관점 오염 방지를 위해 인스턴스 간 격리 필수.
- **핵심 contract (Reverser redesign spec에 locked):** **Reverser output을
  hint로 취급하되 filter로 취급 금지.** 함수 이름이 `safe_input_copy`라도
  VulnHunter는 모든 함수를 전수 분석해야 함.
- **TechniqueKB 참조 (T09):** 자체 분석으로 후보를 찾지 못하면
  `knowledge/techniques/index.md`를 스캔해서 놓친 패턴을 탐색. 관심
  technique은 개별 상세 MD (e.g., `stack_bof.md`)를 읽어 확인. **Tool이나
  loader 없이 file read로 직접 소비.**
- **출력:** candidate list를 Orchestrator에 반환 (state 직접 기록 금지 — Orchestrator가 merge/dedup 후 `omp_patch_state` 호출).

### omp-strategist (T14) ✅ — StrategyAgent

- **역할:** VulnHunter candidate를 받아 **step-by-step exploit plan 설계 + 실행**.
  "이 BOF로 뭘 할 수 있는가? → padding 확인 → ret 제어 → libc leak → ROP"
  식의 incremental proof 계획을 수립.
- **두 가지 task type (Orchestrator가 지정):**
  - **VERIFY:** 단일 primitive를 증명. 하나의 PoC script 작성 + Exploiter로 실행. 성공 시 `poc_script_path` + `gives` 반환. 하나의 SA invocation = 하나의 primitive.
  - **COMBINE:** 이미 verified된 primitive들을 합산. `omp_read_state`로 blackboard를 읽어 source PoC scripts를 파악하고, leak 획득 **로직(코드)**를 합성. **단일 `io = process()` 연결**로 전체 exploit 실행 (multi-connection 금지 — ASLR).
- **Candidate별 병렬 실행:** Orchestrator가 각 라운드에 SA들을 병렬로 spawn. 각 SA는 자기 task에 집중.
- **SA가 Exploiter spawn:** SA는 자기 plan을 실행할 Exploiter를 직접 sub-agent로 spawn (Orchestrator가 아닌 SA가 부모). Exploiter의 실행 결과를 직접 수집해서 retry 여부 결정.
- **Retry logic:** Exploiter 실패 시 결과(디버깅 정보, 메모리 상태)를 받아
  plan을 수정. Max N회 재시도 후 Orchestrator에 실패 보고.
- **TechniqueKB 활용:** `index.md`의 `chain` 필드로 "이 primitive 다음에
  뭘 할 수 있는지" 참조. 상세 MD의 "typical step plan" 섹션 참고.
- **State 직접 쓰기 제거:** plan 결과를 Orchestrator에 반환. `omp_patch_state` 호출 금지 — state 기록은 Orchestrator(sole writer)가 담당.

### omp-exploiter (T16) ✅ — Exploiter (+ Verifier 통합)

- **역할:** StrategyAgent의 step을 받아 **pwntools script 작성 + 실행
  + pwno-mcp로 관찰 + 결과 검증**. 원래 별도 agent이던 Verifier가 여기 통합됨.
- **Spawn 관계:** SA의 sub-agent로 spawn됨 (Orchestrator가 아닌 SA가 부모). SA에서 plan steps를 받아 실행.
- **단일 pwno-mcp container + session_id:** 모든 Exploiter가 1개 container를 공유하되 **서로 다른 session_id**를 사용. pwno-mcp가 session_id별로 GDB 프로세스를 격리 관리. port 분리 불필요.
- **Incremental proof 관찰:** pwno-mcp를 통해 gdb breakpoint 설정, 메모리/
  레지스터/heap 상태를 읽어 step의 성공/실패를 판정. 예: "ret에 0xdeadbeef를
  넣었는데 rip가 실제로 0xdeadbeef인지" 확인.
- **State 직접 쓰기 제거:** 결과를 SA를 통해 Orchestrator에 반환. `omp_patch_state` 호출 금지. `omp_read_state`는 시작 시 context 파악용으로 허용.
- **결과 보고:** 성공 시 step passed → SA에 보고 (SA가 `poc_script_path` + `gives` 결과로 Orchestrator에 반환). 실패 시 observed state (레지스터, 메모리 덤프)를 포함한 상세 보고 → SA.
- **Leak 값 저장 안 함:** libc_base, canary 등 런타임 주소는 ASLR로 실행마다 달라짐 → state에 저장하지 않음. 대신 leak을 **획득하는 코드**(PoC script)가 지식 단위. COMBINE SA가 source PoC를 읽어 단일 connection 안에서 합성.
- **부수 발견 보고:** 예상 못한 leak / heap 상태 / 추가 primitive 발견 시 → 새 candidate로 SA를 통해 Orchestrator에 보고 (Orchestrator가 다음 라운드 cascading 재진입 결정).
- **디버깅 지원:** Reverser artifact의 function map + key annotation의
  BN instruction address를 보고 breakpoint 설정. Mid-function /
  instruction-level 질의는 BN MCP tool 직접 호출.

### ~~omp-verifier~~ (삭제)

> Verifier는 Exploiter에 통합됨 (2026-04-17 exploit pipeline redesign).
> Script 작성 + 실행 + 결과 판정을 한 agent가 수행. 역할 분리의 이점보다
> agent 간 통신 오버헤드 감소가 더 큼.

### omp-discoverer (폐지 — contract-load-detect-split 으로 흡수)

- **이전 역할:** Orchestrator 의 Load stage 전에 "이 challenge 폴더에서
  binary / Dockerfile 이 어디 있는지" discovery.
- **현재:** `.omc/specs/contract-load-detect-split.md` (D1/D2) 로 흡수. 
  `omp_load_challenge` 는 폴더 부트스트랩만, detect 책임은 omp-setup
  Phase 0 (Detect). ELF 후보 2+ 면 setup 이 `setup_blocker.kind=
  "ambiguous-binary"` 박고 stop → orchestrator 가 사용자 disambig 받음 (D5).

---

## 병렬 실행 인프라 (OmO 포팅)

병렬 agent 실행은 opencode의 내장 기능이 아니라 **OmO(oh-my-openagent)가
자체 구축한 인프라**입니다. OmP는 이 패턴을 포팅해야 합니다.

### 핵심 컴포넌트

| 컴포넌트 | 역할 | OmO 참고 파일 |
|----------|------|--------------|
| `omp_task_launch` | fire-and-forget spawn. `{task_id, session_id}` 즉시 반환. category alias 지원 (`setup`/`reverser`/`vulnhunter`/`strategist`/`exploiter`) | `reference/oh-my-openagent/src/tools/delegate-task/` (디자인만 차용) |
| `omp_task_wait_all` / `_wait_any` / `_cancel` | explicit wait/cancel. wait는 state-first check + EventEmitter wake-up. wait_any가 dynamic spawn을 가능하게 함 | (OmP 자체 구현) |
| BackgroundManager | 실행 중 task 추적, polling으로 terminal 감지, `taskEvents` EventEmitter로 wait_* 깨움 | `reference/oh-my-openagent/src/features/background-agent/manager.ts` |
| ConcurrencyManager | 모델별 동시 실행 제한 (기본 5개) | `reference/oh-my-openagent/src/features/background-agent/concurrency.ts` |
| (envsetup 재설계 이후) | container 는 user-managed. omp-setup agent 가 Phase 5 에서 sanity-check (bash `docker ps` + `curl`). 별도 stored field 없이 workspace path 는 `omp-<basename>-<sha8>` derive | `.omc/specs/deep-interview-envsetup-agent.md` |

### 통신 흐름

```
Forward:  Orchestrator → omp_task_launch(agent, prompt) → session.create(parentID) + promptAsync → sub-agent
          → {task_id, session_id} 즉시 반환 (parent는 계속 다른 일 가능)
Backward: sub-agent 세션 idle → BackgroundManager polling → task.status="completed"
          → taskEvents.emit("done", task_id) → 대기 중인 wait_*가 깨어남
          → Orchestrator의 omp_task_wait_all([ids]) / wait_any 호출이 outcome 반환
```

### Session 계층

```
Orchestrator session (depth 0)
  ├─ VH-1 session (depth 1)
  ├─ VH-2 session (depth 1)
  ├─ SA-1 session (depth 1)
  │    └─ Exploiter-1 session (depth 2)
  ├─ SA-2 session (depth 1)
  │    └─ Exploiter-2 session (depth 2)
  └─ SA-3 session (depth 1)
       └─ Exploiter-3 session (depth 2)
```

Max depth = 3 (OmO 기본값). Orchestrator → SA → Exploiter.

### State 동시성 — Sole Writer 패턴 + Blackboard

병렬 agent들이 동시에 `state.json`을 쓰면 충돌. 해결:

- **SA/Exploiter는 state를 직접 쓰지 않음** — `omp_patch_state` 호출 금지
- **SA/Exploiter는 결과를 반환** — session 출력으로 structured result 전달
- **Orchestrator만 `omp_patch_state` 호출** — 결과 수집 후 순차 기록
- **SA/Exploiter는 `omp_read_state`로 읽기만 가능** (시작 시 context 파악용)

**Blackboard 활용:** 각 라운드 후 Orchestrator가 verified primitive의
`poc_script_path` / `gives` / `needs` / `combined_from`을 state에 기록.
다음 라운드 SA는 `omp_read_state`로 blackboard를 읽어 어떤 primitive가
증명됐고 어떤 것을 COMBINE할 수 있는지 파악.

### Operating modes — 자율 vs 사용자 주도 (2026-05-18)

Orchestrator는 두 모드 중 하나로 동작. 매 사용자 turn 시작 시 메시지를
보고 결정. **기본은 자율 모드**, 사용자가 명시적 명령 시 주도 모드로
전환.

| 모드 | 트리거 | LLM autonomy | 종료 조건 |
|---|---|---|---|
| **자율 (default)** | (기본) | 매 도구 호출 LLM이 결정 | 4가지 (아래) |
| **사용자 주도** | "주도로 가" / 명시적 도구 호출 지시 | LLM = thin wrapper, 자율 결정 0 | 사용자가 stop 명령 |

#### 자율 모드 종료 조건 (priority 순)

1. **`flag_found`** — flag 캡쳐 OR shell 획득. 성공 종료.
2. **`stagnated`** — LLM-judged "no progress". 정량 (0 verified + 0 combine + 0 VH new) AND 정성 (LLM 종합 "더 시도할 angle 없음") 둘 다 충족 시 trigger.
3. **`budget_exceeded`** — `state.parallel_config.max_cycles` (default **20**) 초과. **safety net.** 정상 종료 1/2가 먼저 발동되는 것이 기대.
4. **`user_intervention`** — orthogonal. 사용자가 직접 stop.

### Deferred VH transition — Pattern 4b (2026-05-18)

이전 디자인에서는 매 SA round 끝마다 "cascading VH" 단일 launch가 *자동*
실행됐음 (Phase 2.5). 새 디자인은 **단일/ensemble 구분 없음** — LLM이 매
SA 결과 후 "VH가 필요한가?"를 판단하고 `vh_pending` flag를 set. SA loop
**자연 종료** 후 (`ids === []`) flag가 true이면 VH ensemble 재실행
(`state.parallel_config.vh_instance_count` 모두 사용).

**Layer invariant:** VH launch는 **실행 중인 SA가 0개일 때만** 발생.
LLM이 "VH 필요"를 인지해도 즉시 launch하지 않고 flag만 set, SA loop가
자연스럽게 drain되도록 둠. drain 가속 위해 cancel 호출 안 함 — SA 결과는
가능한 한 다 받음.

**Wait 루프 iteration 순서 (CRITICAL):**

```
parse first result → omp_patch_state (record)
                  → maybe omp_task_launch (extra SA / 그냥 둠)
                  → maybe set vh_pending = true
                  → omp_task_wait_any (next iteration)
```

`record-then-launch` 순서가 핵심. SA는 자기 task 시작 시 `omp_read_state`로
blackboard를 읽는데, launch 전에 record를 안 하면 새 SA가 outdated state
보고 같은 primitive 중복 verify 가능. patch_state는 local file write ~수ms로
빠르므로 latency penalty 무시 가능.

---

## 프롬프트 구성 원칙

OmP agent prompt는 공통된 구조를 따릅니다. 새 agent를 만들 때 참고할
템플릿:

### 1. Scope declaration (맨 위)

에이전트가 **무엇을 할 수 있고 무엇을 하면 안 되는지**를 가장 앞에 선언.
예를 들어 Reverser는:

```
## Scope — READ THIS FIRST

**You report what the program IS and what each function DOES.
You do NOT judge exploitability.**

- DO: rename functions, annotate lines, write purpose paragraphs, ...
- DO NOT: identify vulnerabilities, rank exploitability, ...
```

LLM의 attention은 앞쪽에 가장 강하므로 **scope 선언은 무조건 맨 위**.

### 2. Forbidden-words list (cross-cutting rules)

특정 단어를 금지할 때는 **명시적 목록**으로 박음. LLM이 "주의하세요" 같은
vague instruction보다 "다음 단어는 어떤 맥락에서도 쓰지 말 것: X, Y, Z"
명시가 훨씬 adherence가 좋음.

Reverser forbidden list 예:
```
**Forbidden nouns:** vulnerability, exploit, primitive, BOF, overflow, ...
**Forbidden verbs/modals:** may (as in "may be vulnerable"), likely, ...
**Forbidden connectives:** combined with ... forms, indicating, ...
```

에이전트마다 다른 forbidden list를 가질 수 있음 (VulnHunter는
exploitation 언어 허용, Reverser는 금지).

### 3. State management 강제

모든 OmP agent는 `state.json`과 `journal.md`를 **절대 직접 편집하지
않음**. 대신 tool 경유:

```
| Tool | When |
|---|---|
| omp_read_state      | Start of every session or stage |
| omp_patch_state     | After completing any work |
| omp_append_journal  | After every significant step |
```

프롬프트에 "Never write state.json directly" 같은 금지 문구를 명시하고,
tool 사용 순서를 **required sequence**로 박아서 LLM이 빼먹지 않게.

### 4. Required sequence

단계별로 "어느 tool을 어느 순서로 호출하라"를 명시. Numbered list로
박는 게 최고:

```
## Required sequence

0. BN binary setup (step 0: get_binary_status → load_binary if needed)
1. omp_read_state(challenge_dir)
2. Check cache
3. Check source-present mode
4. Run analysis (steps below)
5. Self-review (Pass A + B + C)
6. Write artifact
7. omp_patch_state(...)
8. omp_append_journal(...)
```

### 5. Error handling

각 가능한 실패 케이스에 대해 **무엇을 할지** 명시. 특히 "언제 멈추고
사용자에게 handoff할지":

```
- load_binary fails → stop, omp_append_journal with error, report to user
- decompile_function fails for specific function → skip it, note in journal,
  continue
- BN MCP unreachable → stop, report
- Any partial failure → still call omp_patch_state with partial results
```

### 6. Key principles (맨 아래)

Agent의 핵심 원칙을 bullet list로 재확인. "자기검열" 역할:

```
## Key principles

- Stay neutral always, including in Pass C.
- Apply BN mutations eagerly (rename, retype, comment).
- Write the artifact AFTER Pass A succeeds.
- Never speculate about exploitability — that's VulnHunter's job.
- ...
```

맨 아래의 key principles는 맨 위 scope declaration과 대응하여 **처음과
끝**을 묶는 효과. LLM의 attention이 양쪽 끝에 강하다는 특성을 활용.

---

## Cross-cutting vs template-local 규칙 분리

프롬프트가 길어지면 attention dilution 문제가 생깁니다. OmP는 이를
**규칙의 유효 범위**로 나눠 해결:

| 범위 | 어디에 저장 | 로드 시점 |
|---|---|---|
| **Cross-cutting** (agent 전체에 적용) | System prompt | Agent spawn 시 |
| **Template-local** (특정 artifact 작성 시만 적용) | Template 파일 | `omp_get_template` 호출 시 |

**예시 — Reverser:**

Cross-cutting (system prompt 유지):
- Neutrality + 전체 forbidden-words list
- State management tool 사용법
- Required sequence
- BN MCP tool 목록 + 사용법
- Type inference 4 규칙
- 3-pass self-review

Template-local (research report 템플릿과 함께 로드):
- 보고서 길이 guidance
- Tone (first-person 허용)
- 한국어 보고서의 기술용어 영문 유지 규칙
- 한국어 forbidden-words list
- Heading convention

**Template-local 규칙이 왜 tool 경로에 있어도 괜찮은가:**

처음에는 "tool 응답으로 받으면 adherence가 약해지지 않을까?" 걱정했지만,
오히려 그 반대입니다. LLM은 **최근 context에 recency bias**가 있어서 tool
call 직전에 받은 규칙이 agent spawn 시 받은 system prompt 중간 부분보다
**더 강하게** 기억됩니다. 즉 template-local 규칙은 `omp_get_template`
호출 직후 가장 적절한 타이밍에 로드되어 report 작성 시 fresh하게 적용됩니다.

자세한 설계 근거는 `.omc/specs/deep-interview-reverser-redesign.md`의
Addendum #3 참조.

---

## Template 시스템

Agent가 "특정 형태의 markdown"을 작성해야 할 때, structure와 local rules를
별도 템플릿 파일로 분리합니다. 자세한 내용은 [templates.md](templates.md).

현재 템플릿:
- `reverser-research-en` — 영문 narrative 연구 보고서
- `reverser-research-ko` — 한국어 연구 보고서

미래 추가 예정 (3-agent pipeline):
- VulnHunter candidate 표
- StrategyAgent exploit plan memo
- Exploiter stage execution 보고서 (Verifier 통합)

---

## Agent 추가하려면?

새 agent를 추가할 때 필요한 작업:

1. **`src/agents/<agent-name>.ts` 생성** — `AgentConfig` 반환 factory 함수
2. **`src/agents/definitions.ts`에 등록** — `ompAgentConfigs` map에 1줄 추가
3. **프롬프트 작성** — 이 문서의 "프롬프트 구성 원칙" 따라 scope / forbidden /
   required sequence / error handling / key principles 포함
4. **테스트 작성** — `src/agents/<agent-name>.test.ts`에 description +
   prompt 핵심 문자열 assertion
5. **`bun run build:plugin`** + **`omp` 재시작**
6. **(옵션) 템플릿 추가** — 작성물이 template-based면 `src/templates/`에
   추가 + `omp_get_template` kind에 등록 + verification tool config에
   kind 추가

---

## 관련 파일 요약

| 파일 | 역할 |
|---|---|
| `src/agents/types.ts` | `AgentConfig`, `AgentFactory` 타입 |
| `src/agents/definitions.ts` | `ompAgentConfigs` registry, 기본 모델 |
| `src/agents/omp-orchestrator.ts` | Orchestrator factory + prompt |
| `src/agents/omp-reverser.ts` | Reverser factory + prompt |
| `src/agents/omp-vulnhunter.ts` | VulnHunter factory + prompt (T10) |
| `src/agents/omp-strategist.ts` | StrategyAgent factory + prompt (T14) |
| `src/agents/omp-exploiter.ts` | Exploiter factory + prompt (T16, 가장 복잡) |
| `src/agents/*.test.ts` | Agent 단위 테스트 (프롬프트 핵심 문자열 검증) |

다음 문서에서 **state와 artifact 레이아웃**을 다룹니다 →
[state-and-io.md](state-and-io.md).
