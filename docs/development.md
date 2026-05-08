# Development — 개발 환경 / 빌드 / 테스트 / workflow

이 문서는 OmP를 개발할 때 필요한 **도구 전제**, **빌드/테스트 명령**,
**코드 변경 후 workflow**, **프로젝트 디렉토리 구조**를 정리합니다.

---

## 개발 환경 전제

### 필수

| 도구 | 버전 | 용도 |
|---|---|---|
| **Bun** | ≥ 1.3 | TypeScript runtime + bundler + test runner |
| **Docker** | ≥ 20.x | envsetup이 challenge Dockerfile을 빌드/실행 |
| **Python** | 3.x | pwntools (exploit runtime) |
| **patchelf** | 0.18+ | binary의 interpreter / rpath rewrite |
| **Binary Ninja** | 최신 | Reverser의 decompiler + MCP 서버 (port 9009) |
| **gdb** | 정상 버전 | (나중에 Exploiter 디버깅용) |

### 선택

| 도구 | 용도 |
|---|---|
| **pwndbg** | gdb 확장, heap 분석에 유용 |
| **angr** | 심볼릭 실행 (나중에 Exploiter 전략 분기용) |
| **z3** | 제약 solver (심볼릭 실행과 짝) |
| **one_gadget** | libc one-shot gadget 탐색 |

### 초기 세팅

```bash
# 1. repo 클론 (또는 다른 위치로 이동한 경우 그 경로에서)
cd /abs/path/to/oh-my-pwn

# 2. Bun 의존성 설치
bun install

# 3. 플러그인 / alias / BN bridge 탐지 한 방에 세팅
./scripts/setup-omp.sh

# 4. 새 shell 열기 (alias 반영)
exec zsh   # 또는 `source ~/.zshrc`

# 5. Binary Ninja 실행 + binary 로드 + BN MCP plugin 활성화 (HTTP server port 9009)
#    BN MCP bridge: cd ~/Tools/binary_ninja_mcp && node dist/index.js

# 6. OmP 전용 opencode TUI 실행
omp
```

---

## 빌드

### 플러그인 빌드 (가장 자주 쓰는 명령)

```bash
bun run build:plugin
```

내부 실행:
```bash
bun build src/plugin.ts \
  --outdir dist \
  --target bun \
  --format esm \
  --external @opencode-ai/plugin \
  --external @opencode-ai/sdk \
  --external @modelcontextprotocol/sdk \
  --external @anthropic-ai/sdk \
  --external zod
```

결과: `dist/plugin.js` (단일 파일, 현재 ~130KB).

### 전체 빌드 (플러그인 + CLI reserved)

```bash
bun run build
```

현재 `src/cli/`는 skeleton만 있어서 `build:plugin`과 거의 동등.

### 타입 체크 (빌드 전)

```bash
bun run typecheck
# 실제: tsc --noEmit
```

TypeScript 오류가 있으면 빌드 전에 잡힙니다. CI-like 사용 시 typecheck →
test → build 순.

---

## 테스트

### 전체 실행

```bash
bun test
```

또는

```bash
cd src && bun test
```

(repo 루트에서 `bun test`가 간혹 segfault로 터지는 이슈가 있어서 대안.
원인은 bun 내부 bug로 추정, 영구 fix 전까지 `cd src` workaround 유효.)

현재 테스트 수: **254 passed / 0 failed** (BN 전환 이후 기준). 테스트 파일은
source 파일과 co-located (`src/loader/load-challenge-folder.test.ts` 등).

### 부분 실행

```bash
# 특정 디렉토리만
bun test src/state/

# 특정 파일만
bun test src/agents/omp-reverser.test.ts

# 패턴 매칭
bun test -t "rename_function"
```

### 테스트 범위

| 디렉토리 | 테스트 수 | 커버 영역 |
|---|---|---|
| `src/state/` | ~22 | ChallengeState schema, io, journal, layout |
| `src/loader/` | ~41 | challenge folder loader, binary detection |
| `src/envsetup/` | ~74 | docker runner, ELF mitigations, glibc detect, patchelf, dockerfile parse, 통합 파이프라인 |
| `src/agents/` | ~14 | agent prompt 핵심 문자열 assertion |
| **Total** | **~151** | |

### 테스트 원칙

- **각 library 모듈이 자기 테스트 파일을 co-host.** `src/state/io.ts` →
  `src/state/io.test.ts`
- **DI seam 활용.** Docker runner는 fake implementation 주입 가능 → 외부
  의존성 0으로 전체 파이프라인 통합 테스트 가능
- **Agent 테스트는 프롬프트 핵심 문자열 assertion만.** LLM 동작 자체는
  unit 테스트 불가 — 사용자가 `omp` TUI로 수동 검증
- **Tool 단위 테스트 최소.** 대부분의 tool은 thin wrapper라 backing library
  테스트로 커버됨

---

## 코드 변경 후 workflow

### 일반 코드 변경 (library / state / tool)

```bash
# 1. 수정
vim src/state/challenge-state.ts   # 예: 새 필드 추가

# 2. typecheck
bun run typecheck

# 3. test
bun test

# 4. 플러그인 재빌드
bun run build:plugin

# 5. omp 재시작
# TUI 종료 → exec zsh → omp
```

### Agent prompt 수정

```bash
# 1. 수정
vim src/agents/omp-reverser.ts

# 2. typecheck + test (assertion 몇 개는 프롬프트 핵심 문자열 체크)
bun run typecheck
bun test src/agents/

# 3. 빌드
bun run build:plugin

# 4. omp 재시작 (프롬프트는 dist/plugin.js에 embedded 문자열)
```

**중요:** TUI 내부에서 code/prompt 변경은 반영되지 않습니다. 반드시
build → restart cycle.

### Template 수정

```bash
# 1. 수정
vim src/templates/reverser-research-en.ts

# 2. typecheck + test
bun run typecheck
bun test

# 3. 빌드 (템플릿도 plugin.js에 embedded)
bun run build:plugin

# 4. omp 재시작
```

Template도 TypeScript 파일이라 같은 sync 필요.

### setup-omp.sh 재실행 (repo 경로 이동 후)

다른 디렉토리로 repo를 옮겼거나 새 머신에서 처음 쓸 때:

```bash
./scripts/setup-omp.sh
```

이 스크립트가:
- `dist/plugin.js` 빌드
- 현재 repo 경로로 `~/.config/omp/opencode/opencode.json` 재생성
- `~/Tools/binary_ninja_mcp/` BN MCP bridge 경로 재탐지
- `~/.zshrc`의 `omp` alias 갱신

Dry-run 모드:
```bash
./scripts/setup-omp.sh --dry-run
```

옵션:
- `--no-build` — dist/plugin.js 재사용
- `--no-alias` — zshrc 건드리지 않음
- `--skip-bn` — BN bridge 탐지 skip
- `--bn-bridge <path>` — bridge 경로 명시

---

## 프로젝트 디렉토리 구조

```
oh-my-pwn/
├── src/                          ← TypeScript 소스
│   ├── plugin.ts                 ← 플러그인 entry (opencode가 로드하는 파일)
│   ├── index.ts                  ← library re-exports
│   ├── agents/
│   │   ├── types.ts              ← AgentConfig, AgentFactory 타입
│   │   ├── definitions.ts        ← ompAgentConfigs registry (DEFAULT_MODEL)
│   │   ├── omp-orchestrator.ts   ← Orchestrator factory + prompt
│   │   ├── omp-reverser.ts       ← Reverser factory + prompt
│   │   ├── omp-vulnhunter.ts    ← VulnHunter factory + prompt (T10)
│   │   ├── omp-strategist.ts    ← StrategyAgent factory + prompt (T14)
│   │   ├── omp-exploiter.ts     ← Exploiter factory + prompt (T16)
│   │   └── *.test.ts
│   ├── tools/
│   │   ├── index.ts              ← 10 tool re-exports
│   │   ├── omp-load-challenge.ts
│   │   ├── omp-run-envsetup.ts
│   │   ├── omp-read-state.ts
│   │   ├── omp-patch-state.ts
│   │   ├── omp-append-journal.ts
│   │   ├── omp-get-template.ts
│   │   └── omp-verify-template-output.ts
│   ├── templates/
│   │   ├── index.ts              ← template registry
│   │   ├── reverser-research-en.ts
│   │   └── reverser-research-ko.ts
│   ├── state/                    ← T02 — ChallengeState 영속 layer
│   │   ├── constants.ts
│   │   ├── layout.ts             ← 경로 헬퍼
│   │   ├── challenge-state.ts    ← Zod schema
│   │   ├── io.ts                 ← load/save state
│   │   ├── journal.ts            ← append-only journal
│   │   └── *.test.ts
│   ├── loader/                   ← T03 — challenge folder loader
│   │   ├── challenge-load-error.ts
│   │   ├── binary-detect.ts
│   │   ├── load-challenge-folder.ts
│   │   └── *.test.ts
│   ├── envsetup/                 ← T04 — deterministic env 파이프라인
│   │   ├── envsetup-error.ts
│   │   ├── docker-runner.ts
│   │   ├── docker-build.ts
│   │   ├── docker-extract.ts
│   │   ├── dockerfile-parse.ts
│   │   ├── elf-mitigations.ts
│   │   ├── glibc-detect.ts
│   │   ├── patch-elf.ts
│   │   ├── run-envsetup.ts       ← high-level entry
│   │   └── *.test.ts
│   ├── orchestration/            ← (계획) 병렬 인프라 (OmO 포팅)
│   │   ├── task-tool.ts          ← delegate-task tool (병렬 agent spawn)
│   │   ├── background-manager.ts ← session polling + completion notification
│   │   ├── concurrency.ts        ← 모델별 동시 실행 제한
│   │   └── container-manager.ts  ← pwno-mcp Docker container lifecycle
│   ├── llm/                      ← (reserved, 현재 비어 있음)
│   └── cli/                      ← (reserved, CLI mode future)
├── dist/
│   └── plugin.js                 ← 빌드 산출물 (opencode가 로드)
├── scripts/
│   ├── setup-omp.sh              ← 머신 세팅 one-shot
│   ├── omp-t05.ts                ← T05 수동 envsetup 검증 driver
│   └── omp-t08.ts                ← T08 수동 reverser 검증 driver
├── docs/                         ← 이 디렉토리 (한국어 사용자 가이드)
│   ├── README.md
│   ├── architecture.md
│   ├── agents.md
│   ├── state-and-io.md
│   ├── tools.md
│   ├── templates.md
│   └── development.md
├── knowledge/                    ← TechniqueKB (T09)
│   └── techniques/
│       ├── index.md              ← 전체 카탈로그 (tags/gives/needs/mitigations/glibc/chain)
│       ├── stack_bof.md          ← 상세: 동작 원리, 코드 패턴, exploit 절차
│       ├── ret2win.md
│       ├── fmt_string_read.md
│       ├── fmt_string_write.md
│       └── tcache_poison.md
├── .omc/                         ← 세션 / 스펙 상태 (dotfile)
│   ├── state/
│   │   └── current-task.md       ← session 연속성 single source of truth
│   ├── specs/
│   │   ├── deep-interview-oh-my-pwn.md           ← 원본 요구사항
│   │   ├── deep-interview-reverser-redesign.md   ← Reverser 재설계
│   │   ├── deep-interview-exploit-pipeline.md    ← Exploit pipeline redesign (3-agent)
│   │   └── deep-interview-parallel-orchestration.md  ← 병렬 오케스트레이션 재설계
│   └── research/
│       └── reverser-future-ideas.md              ← post-MVP 아이디어
├── reference/                    ← (gitignored) OmO clone — 패턴 참조용
│   └── oh-my-openagent/
├── test_challenge/               ← (gitignored) 수동 테스트용 CTF
│   └── challenge1/
├── research.md                   ← OmO 아키텍처 분석 (포팅 참고)
├── CLAUDE.md                     ← Claude Code 세션 규칙
├── package.json
├── tsconfig.json
├── bun.lock
└── README.md
```

---

## 수동 검증 스크립트 (T05, T08)

이 스크립트들은 **library layer만 수동 검증**할 때 사용합니다. 사람이
직접 터미널에서 실행해서 실전 CTF 챌린지에 library가 잘 돌아가는지 확인.
Agent 경로 전체를 검증하는 건 아니고, 특정 라이브러리 파이프라인만
isolated하게 돌립니다.

### `scripts/omp-t05.ts` — EnvSetup 수동 검증

```bash
bun scripts/omp-t05.ts <challenge-dir> [--binary <path>] [--dockerfile <path>] [--no-patch]
```

**하는 일:**
1. `loadChallengeFolder` (T03) — challenge 폴더 validate + `.omp/` 초기화
2. `runEnvSetup` (T04) — 실제 docker + libc 추출 + patchelf
3. 결과 summary 출력 (state 필드, 아티팩트 경로, 로그 파일 위치)

**언제 쓰나:**
- 새 CTF 챌린지에 envsetup이 잘 돌아가는지 확인
- Docker/ELF 파싱/patchelf 문제 디버깅
- Agent 없이 library layer만 isolated test

### `scripts/omp-t08.ts` — Reverser 수동 검증 driver

(현재 내용 작성 중일 수 있음 — `current-task.md` 확인)

**언제 쓰나:** Reverser agent를 TUI에서 직접 돌리기 전에 library 파이프라인
smoke test.

---

## 디버깅 팁

### Plugin이 로드되지 않을 때

```bash
XDG_CONFIG_HOME=$HOME/.config/omp opencode debug config 2>&1 | grep -i omp
```

이 명령으로 현재 opencode가 플러그인을 인식하는지 확인. `omp-orchestrator`,
`omp-reverser`, `omp_*` tool들이 출력되어야 정상.

출력 없으면:
1. `dist/plugin.js` 존재 확인 (`ls -lh dist/plugin.js`)
2. `~/.config/omp/opencode/opencode.json` 내용 확인 — `plugin` 배열의
   `file://` 경로가 실제 `dist/plugin.js`를 가리키는지
3. `./scripts/setup-omp.sh` 재실행
4. `stderr`에 "BN MCP not registered" 같은 경고가 있는지 — env var
   설정 누락일 수 있음

### 플러그인이 로드되는데 agent/tool이 안 보일 때

- TUI에서 agent picker가 비어 있으면: `disable: true` 설정된 건지 확인
- 빌드 시점 이슈: `bun run build:plugin` 재실행
- 번들 바이트 크기가 이상하면 (예: 10KB 미만) import 에러로 진단

### 테스트가 반복적으로 segfault 일 때

```bash
# repo 루트에서 실행 시 터지면:
cd src && bun test   # src 디렉토리에서 실행하면 회피됨
```

Bun 내부 이슈로 추정. 영구 fix 전까지 `cd src` workaround 사용.

### BN MCP 연결 실패

1. Binary Ninja 켜져 있는지
2. BN HTTP plugin이 활성화되어 있고 server가 port 9009에 listening 인지
3. BN MCP bridge가 실행 중인지 (`node ~/Tools/binary_ninja_mcp/dist/index.js`)
4. `OMP_BN_BRIDGE_PATH` 환경변수가 설정되어 있는지:
   ```bash
   alias omp   # 출력에 OMP_BN_BRIDGE_PATH=... 포함되어야 함
   ```

---

## Task / session 연속성

OmP는 여러 session에 걸쳐 개발됩니다. 세션 간 연속성은
**`.omc/state/current-task.md`** 가 single source of truth:

- 현재 phase / active task / next action
- 완료된 task 요약 (날짜 + 한 줄)
- Task catalog (T00–T24 상태)

**설계 결정 기록은 current-task.md에 넣지 않음:**
- docs/ 에 반영된 내용 → docs/가 정본
- docs/에 없는 architectural reasoning → `.omc/decisions.md`
- 구현 상세 → git history

새 Claude Code 세션 시작 시 `CLAUDE.md`와 `.omc/state/current-task.md`를
**반드시 먼저 읽습니다**. 그래야 이전 세션의 맥락을 유지할 수 있음.

**TaskCreate tool은 세션별 휘발성이므로**, 중요한 진행 상태는 반드시
`current-task.md`에 기록되어야 재부팅 후에도 살아남습니다.

---

## CI / CD (현재 없음)

MVP 단계라 CI 파이프라인이 아직 설정되지 않았습니다. 개인 개발 기준으로:
- 커밋 전 `bun run typecheck && bun test && bun run build:plugin` 수동
- Git hook 활용 예정 (T24 이후)
- 벤치마크 자동화는 T22 이후

---

## 관련 파일 요약

| 파일 | 역할 |
|---|---|
| `package.json` | Bun scripts, dependencies |
| `tsconfig.json` | TypeScript 설정 (ESNext, bundler moduleResolution) |
| `bun.lock` | 의존성 lockfile |
| `scripts/setup-omp.sh` | 머신 세팅 자동화 |
| `scripts/omp-t05.ts` | EnvSetup library 수동 검증 |
| `scripts/omp-t08.ts` | Reverser library 수동 검증 |
| `CLAUDE.md` | Claude Code 세션 규칙 |
| `.omc/state/current-task.md` | 세션 간 task 연속성 |

---

## 개발 진행 상황

현재 completed / pending task 전체 리스트는 `.omc/state/current-task.md`의
"Task catalog (T00–T24, MVP)" 섹션 참조. 요약 (2026-04-17 기준):

- ✅ **M0 Bootstrap** — T00, T01 (dev env + plugin scaffold)
- ✅ **M1 Input contract + EnvSetup** — T02~T05 (state schema, loader,
  envsetup, user test gate 통과)
- ✅ **M2 Reverser** — T06, T07, T08 모두 완료. BN MCP 연동 + type mutation +
  3-pass self-review + research reports + template infrastructure 구현.
  T08 user test gate 통과 (2026-04-17).
- ✅ **M3 VulnHunter** — T09 TechniqueKB (knowledge/techniques/ 카탈로그 +
  5개 상세 MD) + T10 VulnHunter agent + T11 gate 통과 (challenge2).
- ✅ **M4 StrategyAgent + Exploiter** — T12/T13 skip (패치된 binary 직접 실행,
  별도 tool 불필요). T14 StrategyAgent (verify + combine, retry 3회) +
  T16 Exploiter (pwntools + pwno-mcp Docker gdb 관찰, process()/remote() 두 모드) +
  T15/T17 gate 통과. 248 tests, plugin 161KB.
- ▶ **M5 Orchestrator + Parallel Pipeline** — T18~T21 진행 중.
  병렬 오케스트레이션 재설계: iterative round model, state.json blackboard,
  SA VERIFY/COMBINE task types, single pwno-mcp container + session_id,
  early-exit, PoC code as knowledge transfer.
  OmO 인프라 포팅 (omp_task, omp_background_output, omp_pwno_container tools,
  BackgroundManager, ConcurrencyManager).
  Spec: `.omc/specs/deep-interview-parallel-orchestration.md`
  254 tests (BN 전환으로 ghidra/ 테스트 제거), plugin 161KB.
- ⏸ **M6 Benchmark harness + metric** — T22~T24 대기 (MVP 완료 지점)

각 milestone의 끝에는 **User test gate** 가 있어서 사용자가 직접 품질
확인 후 다음 milestone으로 진행합니다. 자세한 gate 정책은
`.omc/specs/deep-interview-oh-my-pwn.md` 참조.
