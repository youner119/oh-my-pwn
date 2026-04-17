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
const DEFAULT_MODEL = "openai/gpt-5.4"

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

현재 기본값은 `openai/gpt-5.4`. 이유:
- OmP는 JSON 스키마 정확도가 중요 (state patch, ghidra-mcp 호출 등) — GPT-5
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

**현재 구현 상태 (2026-04):**
- ✅ 파이프라인 skeleton 프롬프트
- ✅ Stage 0 (Load) — `omp_load_challenge` tool 호출
- ✅ EnvSetup stage — `omp_run_envsetup` tool 호출
- ✅ Reverse stage — `omp-reverser` delegation
- ⏸ VulnHunt / Strategy / Exploit — sub-agent 미구현, 플레이스홀더만 (3-agent exploit pipeline, Verifier는 Exploiter에 통합)

**Tool 사용:**
- `omp_load_challenge` (첫 stage)
- `omp_read_state` (매 stage 시작)
- `omp_patch_state` (수동 상태 교정 시)
- `omp_append_journal` (user correction 기록)
- `omp_run_envsetup` (EnvSetup stage)

**파일:** `src/agents/omp-orchestrator.ts`

### omp-reverser

**역할:** Challenge binary의 **semantic program understanding**을 생성.
Ghidra-MCP를 통해 함수/변수 rename, inline comment 주입, 타입 refinement
(array / pointer / struct / primitive)를 적용해서 Ghidra DB에 반영하고,
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
- **Pass A (mechanical):** 모든 `rename_function` / `batch_rename_variables`
  / `batch_set_comments` 호출이 성공했는지, 모든 함수에 purpose paragraph가
  있는지, key annotation이 있는지 점검. LLM 호출 없음.
- **Pass B (semantic consistency):** 자기가 만든 artifact를 다시 읽고
  "purpose paragraph가 정말 pseudocode와 일치하는가?" 점검. 불일치 시
  tentative flag.
- **Pass C (full-context refinement):** 전체 프로그램 맥락을 알고 난 뒤
  각 함수를 재annotate. cross-function facts는 허용, cross-function
  judgments는 금지 (forbidden-words 규칙 유지).

**Ghidra 사전 설정 요구사항:** Reverser는 Ghidra GUI에 **정확히 `omp`라는
이름의 project**가 열려 있어야 동작. Step 0에서 `list_instances`로 찾지
못하면 즉시 중단하고 사용자에게 안내.

**Tool 사용:**
- `omp_read_state`, `omp_patch_state`, `omp_append_journal`
- `omp_get_template` — research report 템플릿 로드
- `omp_verify_template_output` — 템플릿 작성물 구조 검증
- Ghidra MCP tools: `list_instances`, `connect_instance`, `import_file`,
  `open_program`, `get_metadata`, `list_functions_enhanced`, `decompile_function`,
  `list_imports`, `list_exports`, `list_strings`, `rename_function`,
  `batch_rename_variables`, `batch_set_variable_types`, `batch_set_comments`,
  `set_function_prototype`, 등

**파일:** `src/agents/omp-reverser.ts` (프롬프트 ~800줄, 가장 복잡한 agent)

---

## Exploit pipeline agents (T10 ~ T17, 구현 완료)

> **Exploit pipeline redesign (2026-04-17).** Deep Interview 10라운드로 결정화.
> Spec: `.omc/specs/deep-interview-exploit-pipeline.md`

### Pipeline 구조

```
Orchestrator
  └→ VulnHunter: find candidates [C1, C2, C3]
       └→ for each candidate (순차, MVP):
            StrategyAgent: design plan [Step1, Step2, Step3]
              └→ for each step:
                   Exploiter: write script → execute → observe (pwno-mcp) → verify
                     ├→ success: next step
                     └→ failure → StrategyAgent redesign (max N retries)
                          └→ exhausted → VulnHunter: next candidate
  └→ all exhausted → user intervention
  └→ shell/flag → DONE
```

**핵심 원칙:**
- **Incremental proof:** 각 step은 하나만 증명 (bof 존재 → ret offset → ROP → shell)
- **역할 분리 = 실패 귀인:** VulnHunter 틀림 = 잘못된 candidate, StrategyAgent 틀림 = 잘못된 plan, Exploiter 틀림 = 잘못된 script
- **Staged escalation:** Exploiter → StrategyAgent → VulnHunter → user 단계적 복귀

### omp-vulnhunter (T10) ✅

- **역할:** Reverser artifact를 읽고 vulnerability candidate 발견 + 랭킹.
  **Bug finder로서 exploit 전략 설계는 하지 않음** — 전략은 StrategyAgent의 몫.
- **핵심 contract (Reverser redesign spec에 locked):** **Reverser output을
  hint로 취급하되 filter로 취급 금지.** 함수 이름이 `safe_input_copy`라도
  VulnHunter는 모든 함수를 전수 분석해야 함.
- **TechniqueKB 참조 (T09):** 자체 분석으로 후보를 찾지 못하면
  `knowledge/techniques/index.md`를 스캔해서 놓친 패턴을 탐색. 관심
  technique은 개별 상세 MD (e.g., `stack_bof.md`)를 읽어 확인. **Tool이나
  loader 없이 file read로 직접 소비.**
- **출력:** `state.json`의 `vuln_candidates` 필드에 candidate list 기록.

### omp-strategist (T14) ✅ — StrategyAgent

- **역할:** VulnHunter candidate를 받아 **step-by-step exploit plan 설계**.
  "이 BOF로 뭘 할 수 있는가? → padding 확인 → ret 제어 → libc leak → ROP"
  식의 incremental proof 계획을 수립.
- **Retry logic:** Exploiter 실패 시 결과(디버깅 정보, 메모리 상태)를 받아
  plan을 수정. Max N회 재시도 후 VulnHunter에게 복귀 (다음 candidate 요청).
- **TechniqueKB 활용:** `index.md`의 `chain` 필드로 "이 primitive 다음에
  뭘 할 수 있는지" 참조. 상세 MD의 "typical step plan" 섹션 참고.
- **출력:** `state.json`의 `stages` 필드에 plan steps 기록 (기존
  StageEntrySchema에 `goal`, `expected_result` 확장).

### omp-exploiter (T16) ✅ — Exploiter (+ Verifier 통합)

- **역할:** StrategyAgent의 step을 받아 **pwntools script 작성 + 실행
  + pwno-mcp로 관찰 + 결과 검증**. 원래 별도 agent이던 Verifier가 여기 통합됨.
- **Incremental proof 관찰:** pwno-mcp를 통해 gdb breakpoint 설정, 메모리/
  레지스터/heap 상태를 읽어 step의 성공/실패를 판정. 예: "ret에 0xdeadbeef를
  넣었는데 rip가 실제로 0xdeadbeef인지" 확인.
- **결과 보고:** 성공 시 step passed + leak 캡처 → 다음 step. 실패 시
  observed state (레지스터, 메모리 덤프)를 포함한 상세 보고 → StrategyAgent.
- **디버깅 지원:** Reverser artifact의 function map + key annotation의
  Ghidra instruction address를 보고 breakpoint 설정. Mid-function /
  instruction-level 질의는 `ghidra-mcp` tool 직접 호출.

### ~~omp-verifier~~ (삭제)

> Verifier는 Exploiter에 통합됨 (2026-04-17 exploit pipeline redesign).
> Script 작성 + 실행 + 결과 판정을 한 agent가 수행. 역할 분리의 이점보다
> agent 간 통신 오버헤드 감소가 더 큼.

### omp-discoverer (T18 sub-step)

- **역할:** Orchestrator의 Load stage 전에 "이 challenge 폴더에서 binary /
  Dockerfile이 어디 있는지" discovery. LLM이 폴더 구조와 README를 읽고
  판단.
- **현재 대체:** 사람이 `omp_load_challenge({ binary, dockerfile })` hint를
  직접 전달 (Orchestrator prompt에 지시).

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

0. Ghidra project setup (step 0 of analysis strategy)
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
- open_program fails → stop, omp_append_journal with error, report to user
- decompile_function fails for specific function → skip it, note in journal,
  continue
- Ghidra MCP unreachable → stop, report
- Any partial failure → still call omp_patch_state with partial results
```

### 6. Key principles (맨 아래)

Agent의 핵심 원칙을 bullet list로 재확인. "자기검열" 역할:

```
## Key principles

- Stay neutral always, including in Pass C.
- Apply Ghidra mutations eagerly.
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
- Ghidra tool 사용법
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
