# Tools — OmP가 제공하는 `omp_*` tool 11개

이 문서는 OmP agent들이 사용하는 **tool 목록**과 각 tool의 **역할 / 시그니처 /
에러 케이스**를 정리합니다.

---

## 왜 tool로 뽑는가

OmP의 기본 원칙: **deterministic 작업은 library로, creative reasoning은
agent로.** LLM은 판단이 필요한 곳에서 빛나고, 반복적·기계적 작업에서는
library가 우월합니다. Tool은 agent와 library를 잇는 인터페이스입니다.

예를 들어 `runEnvSetup()`은 `docker build → libc 추출 → ELF parsing →
glibc detect → patchelf` 파이프라인을 수행합니다. 이 작업은:
- 결정적 (같은 input → 같은 output)
- LLM이 추론으로 재현할 수 없음 (ELF magic byte를 LLM이 직접 parse하면 틀림)
- 실패 케이스가 명확 (docker not running, libc not found 등)

따라서 library 함수로 구현하고 `omp_run_envsetup` tool로 감싸서 agent가
한 번의 호출로 전체 파이프라인을 돌리게 합니다. Agent는 "envsetup 해줘"를
"`omp_run_envsetup({ challenge_dir })`"로 번역하기만 하면 됨.

반대로 "어느 함수를 `safe_input_copy`라고 이름 짓는다"는 LLM 고유 판단이라
tool로 만들지 않고 agent prompt에서 자연어로 처리합니다.

---

## 현재 tool 11개 — 한 눈에

| Tool | 역할 | Library-backed? | 읽기/쓰기 |
|---|---|---|---|
| `omp_load_challenge` | Challenge 폴더 validate + `.omp/` 초기화 | Yes (T03 loader) | 쓰기 |
| `omp_run_envsetup` | Docker build + libc 추출 + patchelf | Yes (T04 envsetup) | 쓰기 |
| `omp_read_state` | `state.json` 로드 | Yes (T02 io) | 읽기 |
| `omp_patch_state` | `state.json` 부분 업데이트 (Zod validated, atomic) | Yes | 쓰기 |
| `omp_append_journal` | `journal.md` append | Yes | 쓰기 |
| `omp_get_template` | 템플릿 문자열 로드 | Yes (src/templates) | 읽기 |
| `omp_verify_template_output` | 템플릿 작성물 구조 검증 | Yes | 읽기 (idempotent) |
| `omp_save_decompiled` | Ghidra HTTP API로 decompile_function 호출 → pseudocode를 LLM 경유 없이 직접 파일로 저장. Reverser가 사용. | No (직접 HTTP) | 쓰기 |
| `omp_task` | 병렬 sub-agent spawn. `run_in_background=true`로 fire-and-forget 실행. task_id 반환. OmO delegate-task 포팅. | Yes (orchestration/) | 쓰기 |
| `omp_background_output` | task_id로 완료된 background task 결과 조회. Orchestrator가 라운드 결과 수집에 사용. | Yes (orchestration/) | 읽기 |
| `omp_pwno_container` | pwno-mcp Docker container lifecycle 관리 (start/stop) + session_id 할당. Exploiter가 사용. | Yes (orchestration/) | 쓰기 |

모두 `src/tools/*.ts`에 구현돼 있고 `src/plugin.ts`에서 session 레벨로
등록됩니다. 원래 7개에서 M5 병렬 인프라 구현으로 3개, pseudocode 저장용 1개 추가됨.

---

## `omp_load_challenge`

**용도:** 새 challenge 폴더를 처음 로드할 때. 파일 시스템 validation,
`.omp/` 디렉토리 초기화, `state.json` 시드, binary sha256 계산, C source
탐지.

**Arguments:**
```ts
{
  challenge_dir: string       // 절대경로 (예: /tmp/ctf/chall1)
  binary?: string             // binary hint (basename / 상대 / 절대경로)
  dockerfile?: string         // Dockerfile hint (basename / 상대 / 절대경로)
}
```

**성공 응답:**
```json
{
  "ok": true,
  "state": { /* 전체 ChallengeState */ },
  "freshlyInitialized": false,
  "shaDrift": false
}
```

`freshlyInitialized`: `.omp/` 이 이 호출로 처음 만들어졌는지. Reload시
`false`.

`shaDrift`: 기존 state의 `binary_sha256`와 현재 binary sha가 다른지. `true`면
사용자가 binary를 교체한 것 — journal에 `## binary sha drift` 블록이 append
되고 state는 건드리지 않음 (재시딩은 사용자 명시 지시 필요).

**에러 케이스:**
- `missing-dir` — 폴더 존재하지 않음
- `not-a-directory` — 경로가 파일임
- `missing-dockerfile` — Dockerfile 없음
- `missing-binary` — binary hint 가리킨 파일 없음
- `ambiguous-binary` — 자동 탐지 시 여러 ELF 후보 — response에 `detail.candidates`
  (후보 경로 리스트) 포함 → 사용자에게 물어보고 `binary` hint로 재호출
- `binary-not-elf` — 파일은 있는데 ELF magic이 아님
- `binary-not-executable` — ELF인데 executable bit 없음

**사용 맥락:** Orchestrator pipeline의 **Stage 0 (Load)**. 매 challenge의
첫 tool 호출. 재실행 시에는 cache hit으로 빠르게 반환 (파일 재스캔 없이
state.json 재로드).

**파일:** `src/tools/omp-load-challenge.ts`, backed by
`src/loader/load-challenge-folder.ts`

---

## `omp_run_envsetup`

**용도:** EnvSetup 파이프라인 full execution. Docker image 빌드, libc/ld
추출, glibc version detect, ELF mitigations 파싱, patchelf로 binary
interpreter/rpath rewrite.

**Arguments:**
```ts
{
  challenge_dir: string
  patch?: boolean   // 기본 true. false면 patchelf skip
}
```

**성공 응답:**
```json
{
  "ok": true,
  "state": { /* 업데이트된 ChallengeState */ },
  "rebuilt": true,          // docker build 실제로 돌았는지 (cache hit이면 false)
  "staticLinked": false,
  "patched": true           // patchelf가 이번 run에서 적용됐는지
}
```

**에러 케이스** (EnvSetupError.kind):
- `state-missing` — T03 loader가 먼저 돌지 않았음
- `docker-not-available` — `docker` 명령 없음 / 권한 없음
- `docker-build-failed` — detail에 `exitCode`, `buildLogPath` (사용자가
  해당 로그 파일 읽어서 진단)
- `libc-not-found` — docker image의 표준 경로에 libc 없음.
  detail.candidatesTried (시도한 9개 경로), detail.imageListing
  (`/lib*` listing — 진단용)
- `elf-parse-error` — binary가 valid ELF 아님
- `extraction-failed` — `docker cp` 실패
- `patchelf-not-available` — `patchelf` 명령 없음 (`apt install patchelf`)
- `patchelf-failed` — patchelf exit code 0 아님 (원본은 백업에 보존)

**사용 맥락:** Orchestrator pipeline의 **EnvSetup stage**. Load 다음에
호출. 재실행 시 idempotent (docker image cache hit 가능, patchelf는
백업에서 복원 후 재패치).

**주의:** 이 tool은 agent가 bash로 docker/readelf/patchelf를 직접 치는 것을
**대체**합니다. Agent prompt에 "bash로 docker 치지 말 것" 명시.

**파일:** `src/tools/omp-run-envsetup.ts`, backed by
`src/envsetup/run-envsetup.ts`

---

## `omp_read_state`

**용도:** 현재 challenge의 `state.json` 읽기. Agent가 매 session/stage
시작 시 맨 먼저 호출해서 "지금 어디까지 왔는지" 파악.

**Arguments:**
```ts
{ challenge_dir: string }
```

**성공 응답:**
```json
{ "ok": true, "state": { /* ChallengeState 전체 */ } }
```

**에러 케이스:**
- `state_not_found` — `.omp/state.json` 없음 (T03 loader 먼저 실행 필요)
- `state_corrupt` — 파일은 있는데 Zod schema 검증 실패 (`statePath` 포함)
- `internal_error` — 기타

**사용 맥락:** 모든 OmP agent의 **첫 호출**. Required sequence에 명시:
```
1. omp_read_state(challenge_dir) — get binary_path, source_present, ...
```

**파일:** `src/tools/omp-read-state.ts`

---

## `omp_patch_state`

**용도:** `state.json`의 특정 필드만 부분 업데이트. Shallow merge 후 Zod
재검증, 실패 시 파일 건드리지 않음. 성공 시 atomic write.

**Arguments:**
```ts
{
  challenge_dir: string
  patch: Record<string, unknown>   // 부분 ChallengeState 필드
}
```

**예시:**
```json
{
  "challenge_dir": "/tmp/ctf/chall1",
  "patch": {
    "reverser_summary_path": "/tmp/ctf/chall1/.omp/artifacts/reverser-analysis.md",
    "reverser_analyzed_at": "2026-04-15T06:01:00.239Z"
  }
}
```

**Protected fields (자동 제거):** `challenge_dir`, `schema_version`,
`binary_path`. 이 셋은 loader 초기 시딩 외에는 변경 금지라 patch에서 자동
stripping됨.

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
- 예: Reverser가 마지막에 3개 path + timestamp를 한 번의 `omp_patch_state`로
  기록

**파일:** `src/tools/omp-patch-state.ts`

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
- Ghidra 셋업 실패: "Ghidra 'omp' project not running"

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

## `omp_save_decompiled`

**용도:** Ghidra HTTP API에 직접 연결해서 `decompile_function`을 호출하고,
결과 pseudocode를 LLM 출력을 경유하지 않고 파일로 직접 저장. LLM이 긴
pseudocode를 `...`으로 축약하는 문제를 방지.

**Arguments:**
```ts
{
  challenge_dir: string        // 절대경로
  function_address: string     // hex 주소 (예: "0x00152700")
  filename: string             // 확장자 없는 파일명 (예: "afterimage_main")
}
```

**출력 경로:** `<challenge_dir>/.omp/artifacts/pseudocode/<filename>.txt`

**성공 응답:**
```json
{
  "ok": true,
  "path": "/tmp/ctf/chall1/.omp/artifacts/pseudocode/afterimage_main.txt",
  "lines": 782,
  "function_address": "0x00152700",
  "code": "/* full pseudocode ... */"
}
```

`code` 필드에 전체 pseudocode가 포함되어 반환됩니다. Reverser는 이
응답의 `code`를 분석용(purpose paragraph, stack frame, key annotations)으로
사용하고, 파일은 이미 직접 저장되었으므로 `write` tool로 따로 쓸 필요 없음.

**데이터 흐름:**
```
Ghidra HTTP API (port 8089) → omp_save_decompiled tool → 파일 직접 저장
                                                        → LLM에 code 반환 (분석용)
```
LLM 출력을 경유하지 않으므로 truncation 불가능.

**에러 케이스:**
- `connection_failed` — Ghidra GUI가 port 8089에서 응답하지 않음
- `decompile_failed` — Ghidra가 해당 주소의 함수를 찾지 못함
- `empty_result` — decompile 결과가 비어있음

**환경변수:** `OMP_GHIDRA_GUI_PORT` (기본 8089)

**사용 맥락:** Reverser Analysis strategy step 7. `decompile_function` +
`write` 조합을 대체. Reverser 프롬프트에 "Do NOT call `decompile_function` +
`write` manually for step 7" 명시.

**파일:** `src/tools/omp-save-decompiled.ts`

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
| `src/tools/index.ts` | 11개 tool re-export |
| `src/tools/omp-*.ts` | 각 tool 구현 (thin wrapper over library) |
| `src/plugin.ts` | tool map 등록 (session 레벨) |
| `src/loader/` | T03 library (load_challenge backed) |
| `src/envsetup/` | T04 library (run_envsetup backed) |
| `src/state/` | T02 library (read_state / patch_state / append_journal backed) |
| `src/templates/` | get_template backed (템플릿 string 저장소) |

다음 문서에서 **템플릿 시스템의 세부**를 다룹니다 → [templates.md](templates.md).
