# Tools — OmP가 제공하는 `omp_*` tool 14개

이 문서는 OmP agent들이 사용하는 **tool 목록**과 각 tool의 **역할 / 시그니처 /
에러 케이스**를 정리합니다.

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

## 현재 tool 14개 — 한 눈에

| Tool | 역할 | Library-backed? | 읽기/쓰기 |
|---|---|---|---|
| `omp_load_challenge` | Challenge 폴더 부트스트랩 (`.omp/` 초기화 + `state.workspace_root` 시드). binary/dockerfile/source 식별은 omp-setup Phase 0 (Detect) — `.omc/specs/contract-load-detect-split.md` D1. | Yes (loader) | 쓰기 |
| `omp_read_state` | `state.json` 로드 | Yes (T02 io) | 읽기 |
| `omp_patch_state` | `state.json` 부분 업데이트 (Zod validated, atomic) | Yes | 쓰기 |
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

모두 `src/tools/*.ts` / `src/orchestration/*.ts`에 구현돼 있고
`src/plugin.ts`에서 session 레벨로 등록됩니다. 원래 7개 + M5 병렬 인프라
+ pwno 호환성 수정 + 4-tool cutover (2026-05-18). 이후 BN 전환으로
`omp_save_decompiled` 제거, pwno 호환성 수정으로 `omp_pwno_container`
제거. **envsetup 재설계 (T12-T14)** 로 `omp_run_envsetup` /
`omp_stage_challenge` / `omp_pwno_status` 3개가 폐지되고 omp-setup
agent + atomic 4개 (`omp_setup_*`) 가 흡수.

---

## `omp_load_challenge`

**용도:** 새 challenge 폴더를 처음 로드할 때 `.omp/` 디렉토리를 부트스트랩.
binary / Dockerfile / source 식별은 **하지 않는다** — 그건 omp-setup Phase 0
(Detect) 의 책임. 본 tool 은 디렉토리 존재 검증 + `.omp/{state.json,
journal.md, artifacts/, logs/, exploit/}` 초기화 + (옵션) `state.workspace_root`
시드만 수행. spec: `.omc/specs/contract-load-detect-split.md` (D1).

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
  "state": { /* 전체 ChallengeState */ },
  "freshlyInitialized": false
}
```

`freshlyInitialized`: `.omp/` 이 이 호출로 처음 만들어졌는지. Reload시
`false`. binary 교체 시 sha drift 감지는 폐지 — `rm -rf .omp/` 후 reload
가 정본 (D4).

**에러 케이스:**
- `missing-dir` — 폴더 존재하지 않음
- `not-a-directory` — 경로가 파일임

binary 후보 0개 / 2개 이상, Dockerfile 부재, ELF magic 검증 등은 모두
omp-setup Phase 0 (Detect) 가 처리. ELF 후보 여러 개면 setup 이
`state.setup_blocker = {kind: "ambiguous-binary", candidates[], message}` 박고
stop → orchestrator 가 사용자 disambig 받아 `omp_patch_state` 로
`binary_input_path` 박고 blocker clear → setup 재시작 (D5).

**사용 맥락:** Orchestrator pipeline 의 **Stage 0 (Load)** — 매 challenge
의 첫 tool 호출. 재실행 시 idempotent: 기존 state.json 그대로 로드.

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

**Protected fields (자동 제거):** `challenge_dir`, `schema_version` 만.
이 둘은 `omp_load_challenge` 초기 시딩 외에 변경 금지라 patch 에서 자동
stripping. 그 외 모든 필드는 patchable —
`binary_input_path` / `binary_input_sha256` / `dockerfile_path` /
`source_present` / `source_paths` 는 omp-setup Phase 0 (Detect) 가 쓰고,
orchestrator 도 D5 disambig 시 `binary_input_path` 박음. spec:
`.omc/specs/contract-load-detect-split.md` D2/D6.

**`etc` write 정책 (POLICY-ENFORCED, D7):** `etc` (free-form
`Record<string, unknown>`) 는 strip 대상이 *아니지만* 정책상 **omp-setup /
omp-orchestrator 만 write 가능**. omp-reverser / omp-vulnhunter /
omp-strategist / omp-exploiter 는 read 만 — patch 에 `etc` 포함시키면
orchestrator audit 이 잡고 revert. 위반 누적 시 physical enforcement
(patch_state.context.agent 확인) 로 escalate.

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
| `src/tools/index.ts` | tool re-export (14개 — state IO + load + 4-tool task + 4-tool omp_setup_*) |
| `src/tools/omp-*.ts` | 각 tool 구현 (thin wrapper over library 또는 omp-setup atomic) |
| `src/orchestration/index.ts` | task surface (`omp_task_*` 4개) re-export |
| `src/plugin.ts` | tool map 등록 (session 레벨) |
| `src/loader/` | load-challenge backed |
| `src/envsetup/` | docker-build / docker-extract / patch-elf library — atomic omp_setup_* 가 wrap (legacy `run-envsetup.ts` 437 줄은 T19 deprecation 영역) |
| `src/state/` | read_state / patch_state / append_journal backed |
| `src/templates/` | get_template backed (템플릿 string 저장소) |
| `src/agents/omp-setup.ts` | atomic 4개 호출 흐름 제어 (Phase 0-6) |

다음 문서에서 **템플릿 시스템의 세부**를 다룹니다 → [templates.md](templates.md).
