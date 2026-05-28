# oh-my-pwn (OmP) Documentation

> CTF pwnable 자동 솔버 multi-agent harness — **opencode 독립 플러그인**

이 문서는 OmP 프로젝트를 처음 보는 사람이 전체 구조를 이해할 수 있도록
정리한 가이드입니다. 개발이 진행되면서 계속 갱신됩니다.

---

## OmP가 무엇인가

**oh-my-pwn (OmP)** 는 Linux glibc user-space CTF pwnable 문제를 **가능한
한 자율적으로** 풀도록 설계된 multi-agent harness입니다. 바이너리와
Dockerfile 한 쌍만 있으면 다음 파이프라인을 agent들이 순차적으로 실행합니다:

```
Load → EnvSetup → Reverse → VulnHunt (ensemble) → [Strategy ↔ Exploit (parallel)] → Flag
```

각 단계는 전용 agent가 담당하며, 상태는 challenge 폴더 내부의 `.omp/`에
persistent하게 저장됩니다. 사람은 언제든지 **prompt 채널**로 개입해서
잘못된 판단을 교정할 수 있습니다 (`journal.md`는 read-only, 수정은
agent에게 말로).

**Exploit pipeline (3-agent model, 2026-04-17 redesign, parallel orchestration 2026-04-25):**
- **VulnHunter** — bug finder. Reverser output에서 취약점 후보 발견.
  ensemble 병렬 분석, Orchestrator가 merge/dedup
- **StrategyAgent** — exploit designer. 두 가지 task type:
  - **VERIFY**: 단일 primitive를 증명하는 PoC script 작성 + 실행. 성공 시 `poc_script_path` + `gives` 반환.
  - **COMBINE**: verified primitives를 합산. source PoC scripts의 leak **logic(코드)**을 합성하여 단일 connection exploit 완성.
- **Exploiter** — executor + verifier (통합). Script 작성 → 실행 → pwno-mcp로 관찰 → 판정.
  SA가 직접 spawn. 단일 pwno-mcp container, session_id로 격리.

Phase 2는 **반복 라운드 모델**: 각 라운드에서 SA들이 병렬로 VERIFY/COMBINE 실행.
`state.json`이 shared blackboard — verified primitives (poc_script_path, gives, needs)가
라운드 간에 누적되며 다음 라운드 SA가 참조. Orchestrator가 임의 SA의 flag 획득 시
나머지 즉시 취소 (early-exit). **Leak 값은 저장 안 함** (ASLR으로 무의미) —
PoC code가 knowledge transfer 메커니즘.

실패 시 staged escalation: Exploiter → StrategyAgent 재설계 → VulnHunter
다음 candidate → 전체 소진 시 사용자 개입. Cascading: 확인된 취약점에서
파생 primitive 발견 + Exploiter 부수 발견 → 새 candidate로 재진입.

### 핵심 설계 원칙

- **Autonomous-first with prompt-driven human intervention.** 기본은
  agent가 자율적으로 진행. 막히거나 잘못 판단하면 사람이 prompt로 교정.
  사용자가 파일을 직접 편집하는 "async file edit" 시나리오는 없음.
- **독립 opencode 플러그인.** oh-my-openagent(OmO)와 별개. `@opencode-ai/plugin`
  인터페이스를 직접 구현. OmO는 아키텍처 패턴 **참고용**(`reference/`에 clone).
- **Deterministic 작업은 library로, creative reasoning은 agent로.** docker
  build, ELF parsing, glibc detection, patchelf 같은 고정 작업은 TypeScript
  library (envsetup/, loader/, state/). 함수 이름 짓기, vuln primitive 판단,
  exploit 작성 같은 판단 작업은 agent prompt.
- **Incremental proof.** 각 exploit step은 최소 단위만 증명. "bof 존재 확인
  → ret offset 확인 → ROP chain 동작 확인 → shell". 한 번에 monolithic
  exploit을 작성하지 않고, 단계별로 검증하며 쌓아감.
- **Parallel-first with ensemble consensus.** VulnHunter는 ensemble로
  병렬 분석하여 합의 기반 candidate list 생성. StrategyAgent는 반복 라운드
  모델로 병렬 실행. Orchestrator만 state를 쓰는 sole-writer 패턴으로 동시
  쓰기 충돌 회피.
- **Shared blackboard.** `state.json`이 라운드 간 공유 blackboard.
  verified primitive의 `poc_script_path` / `gives` / `needs` 필드가
  다음 라운드 SA에게 노출되어 COMBINE 전략 수립에 활용.
- **PoC code as knowledge transfer.** Leak 값(libc_base, canary 등)은
  ASLR으로 실행마다 달라지므로 저장 안 함. 대신 leak을 **획득하는 코드**
  (PoC script)를 지식 단위로 관리. COMBINE SA는 source PoC를 읽어 단일
  connection으로 합성.
- **역할 분리로 실패 귀인 명확화.** VulnHunter 틀림 = 잘못된 candidate,
  StrategyAgent 틀림 = 잘못된 plan, Exploiter 틀림 = 잘못된 script.
- **Neutrality discipline.** Reverser는 "취약점 같다"는 판단을 하지 않음.
  사실만 기록. 취약점 판단은 VulnHunter 전용. 프롬프트에 forbidden-words
  list로 강제.
- **Korean-first user experience.** 사용자 언어는 한국어 기본, 기술용어는
  영문 유지. Agent 출력(journal, research report 한국어판)도 동일.

### 입력 계약

| 입력 | 필수/선택 | 용도 |
|---|---|---|
| Binary (ELF 64-bit) | 필수 | 분석 및 exploitation 대상 |
| Dockerfile / docker-compose.yml | 필수 | 원격 환경 로컬 재현, libc/ld 추출 |
| C 소스 (`*.c`) | 선택 | 있으면 Reverser는 skip, VulnHunter가 소스 직접 분석 |
| 원격 서버 | 사용 안 함 | Dockerfile로 로컬 reproduction만 사용 |

### 지원 범위 (MVP)

- **대상:** Linux user-space pwnable, **ELF x86_64**
- **glibc**: benchmark 문제가 쓰는 버전만 (예정: 2.27 ~ 2.35+)
- **OUT of scope:** 32-bit, ARM, kernel pwn, browser pwn, web/crypto/misc CTF 장르

---

## 빠른 시작

```bash
# 1. repo 위치에서 플러그인 세팅
./scripts/setup-omp.sh

# 이 스크립트가 하는 일:
#   - dist/plugin.js 빌드
#   - ~/Tools/binary_ninja_mcp/dist/index.js 자동 탐지 (또는 interactive prompt)
#   - ~/.config/omp/opencode/opencode.json 생성 (file:// 경로로 플러그인 등록)
#   - ~/.zshrc에 alias omp 추가
#   - opencode debug config로 플러그인 로드 확인

# 2. 새 쉘 시작
source ~/.zshrc

# 3. Binary Ninja 실행 + BN HTTP plugin 활성화 (port 9009)
#    BN MCP bridge 시작: cd ~/Tools/binary_ninja_mcp && node dist/index.js

# 4. OmP 전용 opencode TUI 시작
omp
```

이후 TUI의 agent picker에서 `omp-orchestrator` 선택 후 challenge 폴더
경로를 주면 됩니다.

---

## 문서 목차 (읽을 순서)

1. **[architecture.md](architecture.md)** — OmP가 opencode 플러그인으로
   어떻게 동작하는지. `@opencode-ai/plugin` 인터페이스, config/tool hook,
   빌드-배포 파이프라인.
2. **[agents.md](agents.md)** — 각 agent의 역할과 프롬프트 구성 원칙.
   factory pattern, `AgentConfig` 타입, 현재/미래 agent 목록,
   cross-cutting vs template-local 규칙 분리.
3. **[state-and-io.md](state-and-io.md)** — `<challenge-dir>/.omp/` 레이아웃.
   `state.json` (ChallengeState Zod schema), `journal.md` (append-only),
   `artifacts/` (reverser-analysis, research reports, libc/ld, patched
   binary). 상태 mutation 원칙.
4. **[tools.md](tools.md)** — 현재 18개 `omp_*` tool의 역할과 시그니처.
   왜 tool로 뽑았는지 (deterministic ops는 LLM이 아닌 library).
5. **[templates.md](templates.md)** — 템플릿 시스템. Reverser research
   report가 어떻게 template 파일 + tool을 통해 생성되는지. 향후
   VulnHunter/Exploiter도 같은 패턴 재사용 예정.
6. **[development.md](development.md)** — 개발 환경 전제, 빌드,
   테스트, 코드 변경 후 workflow, 프로젝트 디렉토리 구조.

### 심화 자료

- **`.omc/specs/deep-interview-oh-my-pwn.md`** — 프로젝트 원본 요구사항
  spec (deep-interview 6라운드 transcript, ontology, acceptance criteria).
- **`.omc/specs/deep-interview-reverser-redesign.md`** — Reverser agent
  재설계 spec (추가 6라운드 interview, type mutation / stack frame /
  research reports / BN MCP 연동 결정 과정).
- **`.omc/state/current-task.md`** — 세션 간 task 연속성의 single source
  of truth. *현재 active phase + Open blockers + Session continuity*.
  완료된 작업은 `prev-task.md` 로, 생각 중인 후보는 `backlog.md` 로 분리.
- **`.omc/state/prev-task.md`** — 완료된 작업 아카이브 (envsetup 재설계,
  Knowledge integration phase K-series, M0–M5 main 등). 최신 우선 정렬.
- **`.omc/state/backlog.md`** — 생각 중인 작업 후보 idea backlog.
  Deep-interview 시 `.omc/specs/` 로 spec graduate, 진입 결정 시
  `current-task.md` active phase 로 이동, 폐기 시 strikethrough 후 유지.
- **`.omc/specs/deep-interview-parallel-orchestration.md`** — 병렬
  오케스트레이션 파이프라인 재설계 spec (VH ensemble, 병렬 SA+Exploiter,
  cascading, sole-writer 패턴).
- **`research.md`** — OmO 아키텍처 분석 (포팅 시 참고).
- **`CLAUDE.md`** — Claude Code 세션 규칙 (이 repo에 들어왔을 때 반드시
  먼저 읽을 파일).

---

## 이 문서는 계속 갱신됩니다

OmP는 MVP 단계(T00 ~ T24)이므로 아키텍처와 인터페이스가 변할 수 있습니다.
문서가 코드와 어긋난 부분을 발견하면 **문서를 수정해서 동기화**해주세요 —
새 agent가 추가되거나 기존 agent의 프롬프트가 바뀌거나 tool이 늘거나 등.
`.omc/state/current-task.md`의 후속 로그를 따라 무엇이 언제 바뀌었는지
추적할 수 있습니다.
