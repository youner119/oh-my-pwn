# Templates — 재사용 가능한 작성물 스켈레톤

이 문서는 OmP의 **template 시스템**을 설명합니다. Agent가 일정한 형태의
artifact를 작성할 때 structure와 local rules를 별도 파일로 분리하는 패턴.

---

## 왜 템플릿 시스템이 필요한가

Agent prompt는 길어질수록 **attention dilution** 문제가 생깁니다. 중요한
규칙이 5,000 tokens의 instruction 속에 묻혀버리면 LLM이 따르지 못합니다.

OmP는 이 문제를 **규칙의 유효 범위별 분리**로 해결합니다:

| 규칙 범위 | 저장 위치 | 로드 시점 |
|---|---|---|
| **Cross-cutting** (agent 전체에 적용) | Agent system prompt | Agent spawn 시 |
| **Template-local** (특정 artifact 작성 시만 적용) | Template 파일 | `omp_get_template` 호출 시 |

**예시 — Reverser:**

Cross-cutting 규칙 (Reverser system prompt에 상주):
- Neutrality + 전체 forbidden-words list (rename 이름, BN comment, purpose
  paragraph 등 모든 산출물에 적용)
- State management tool 사용법
- Required sequence 개요
- BN MCP tool 사용법
- Type inference 4 규칙
- 3-pass self-review

Template-local 규칙 (research report 템플릿 파일에 상주):
- 보고서의 audience / tone
- Length guidance (hard limit 없음, soft guideline만)
- Neutrality **reminder** (system prompt 규칙을 pointer로 참조, full list
  복제 안 함)
- KO-specific: 한국어 prose 규칙, 기술용어 영문 유지, 한국어 forbidden-words
  list, heading convention

---

## Template 작성물이 왜 tool 응답으로 와도 adherence가 약해지지 않는가

처음엔 직관적으로 "system prompt에 있는 게 tool 응답보다 강한 signal"이라고
생각하기 쉽지만 실제로는 반대입니다.

LLM은 **recency bias**가 있어서 **최근 context**에 가장 집중합니다.
System prompt의 5000 tokens 뒤쪽에 묻힌 규칙보다, `omp_get_template` 호출
직후에 받은 규칙이 훨씬 fresh하게 기억됩니다. 따라서 template-local 규칙은
`omp_get_template` 경유로 로드되는 게 **작업 시점 attention 우위**를
얻습니다.

그래서 OmP 설계:
- 모든 작업에 적용되는 규칙 → system prompt (어디에 써도 적용됨)
- 특정 작업 시점에만 필요한 규칙 → 해당 tool 응답에 담음

자세한 근거는 `.omc/specs/deep-interview-reverser-redesign.md`의
Addendum #3 참조.

---

## Template 파일 구조

모든 템플릿은 동일한 markdown 구조를 가집니다:

```markdown
# Template: <kind>

## Rules for filling this template

<template-local 규칙들. 자연어 prose 또는 bullet list.
audience / tone / length / neutrality reminder / 언어별 규칙 등.>

## Skeleton

<skeleton에 대한 부연 설명 1-2 문장>

\`\`\`markdown
# <artifact H1 title>

<placeholder 1: description>

## <section 1 name>

<placeholder 2: description>

## <section 2 name>

<placeholder 3: description>

...
\`\`\`
```

**중요한 convention:**
- Skeleton은 반드시 ` ```markdown ... ``` ` 코드 블록 안에
- 섹션 heading은 `## <name>` (H2)
- Placeholder는 `<description>` angle-bracket 형태 — verification tool이
  `<...>` 를 미치환으로 감지
- Agent는 skeleton **내부**만 verbatim으로 emit하고 \`\`\`markdown fence는
  출력하지 않음

### Skeleton parsing

`omp_verify_template_output`이 템플릿 파일을 파싱해서 H2 heading 목록을
추출합니다. 파싱 로직 ( `src/tools/omp-verify-template-output.ts` ):

```ts
function extractRequiredSectionsFromTemplate(template: string): string[] {
  const skeletonMatch = template.match(
    /## Skeleton[\s\S]*?```markdown\n([\s\S]*?)\n```/
  )
  if (skeletonMatch === null) return []
  const skeleton = skeletonMatch[1] ?? ""
  const headings: string[] = []
  for (const line of skeleton.split("\n")) {
    const h2Match = line.match(/^## (.+?)\s*$/)
    if (h2Match !== null) {
      headings.push((h2Match[1] ?? "").trim())
    }
  }
  return headings
}
```

파싱된 heading 리스트가 verification의 "Required sections" check에
사용됩니다. 새 섹션을 templates에 추가하면 자동으로 verification에
반영됨.

---

## 현재 템플릿 목록

### `reverser-research-en`

- **파일:** `src/templates/reverser-research-en.ts`
- **목적:** Reverser의 영문 narrative 연구 보고서 (`reverser-research.md`)
- **사용 agent:** `omp-reverser`

**Rules 섹션 내용:**
- Audience: 사람 사용자 (primary) + downstream agents (secondary)
- Tone: first-person singular 허용 ("I renamed X to Y")
- Length: hard limit 없음, 일반 CTF 300-800 words
- Neutrality reminder (system prompt pointer)
- Placeholder 치환 규칙
- Section order 보존 규칙

**Skeleton 섹션 (필수 섹션 7개):**
1. `## Executive summary`
2. `## Analysis approach`
3. `## What each function does`
4. `## Types I applied`
5. `## Data entry points`
6. `## Stack frames of interest`
7. `## Handoff notes`

### `reverser-research-ko`

- **파일:** `src/templates/reverser-research-ko.ts`
- **목적:** Reverser의 한국어 narrative 연구 보고서 (`reverser-research.ko.md`)
- **사용 agent:** `omp-reverser`

**Rules 섹션 내용 (KO-specific):**
- Audience: Korean-speaking pwn operator
- Tone: 자연스러운 한국어 prose (번역체 금지)
- Full translation (영문판 축약 금지)
- Technical terms 영문 유지 규칙 (BN MCP tool names, C/libc function
  names, `stack`/`heap`/`canary`/`rbp`/`RELRO`/`PIE`/`NX` 등)
- **Korean 기술용어 번역 금지 목록:** `스택`, `힙`, `캐나리`, `카나리`,
  `버퍼` — 이들이 등장하면 verification 실패
- **Forbidden Korean words list:** `취약점`, `취약성`, `익스플로잇`,
  `오버플로우`, `유출`, `누출`, `악용` 등
- Dual self-check (English + Korean forbidden list 양쪽 대조)
- Heading convention: `## Executive summary (요약)` 형태로 영문 heading +
  옵션 한국어 parenthetical

**Skeleton 섹션 (영문판과 동일 구조, 한국어 제목):**
1. `## Executive summary (요약)`
2. `## Analysis approach (분석 접근)`
3. `## What each function does (함수별 역할)`
4. `## Types I applied (적용한 타입)`
5. `## Data entry points (입력 진입점)`
6. `## Stack frames of interest (주요 stack frame)`
7. `## Handoff notes (인수인계)`

---

## 템플릿 저장 방식

OmP 템플릿은 **TypeScript `.ts` 파일에서 const string export**로
저장됩니다. 예:

```ts
// src/templates/reverser-research-en.ts
export const reverserResearchEnTemplate = `# Template: reverser-research-en

## Rules for filling this template
...

## Skeleton
...`
```

**왜 `.ts` 파일인가 ( `.md` 파일이 아니라 ):**

- **번들 단순:** `bun build`가 그냥 import로 처리. `.md` 파일을 번들에
  포함하려면 별도 build plugin이나 raw import assertion이 필요한데,
  bun의 지원이 버전마다 달라서 fragile.
- **편집 가능:** `.ts` 파일 안에 template literal 문자열로 들어가 있어도
  대부분 에디터가 markdown syntax 유지. 편집 경험 차이 거의 없음.
- **Type-safe registry:** `src/templates/index.ts`가 const object로
  등록하므로 `OmpTemplateKind` 타입 자동 추론.

**Registry (`src/templates/index.ts`):**

```ts
import { reverserResearchEnTemplate } from "./reverser-research-en"
import { reverserResearchKoTemplate } from "./reverser-research-ko"

export const OMP_TEMPLATES = {
  "reverser-research-en": reverserResearchEnTemplate,
  "reverser-research-ko": reverserResearchKoTemplate,
} as const

export type OmpTemplateKind = keyof typeof OMP_TEMPLATES

export function getOmpTemplate(kind: string): string | null {
  return (OMP_TEMPLATES as Record<string, string>)[kind] ?? null
}

export function listOmpTemplateKinds(): string[] {
  return Object.keys(OMP_TEMPLATES)
}
```

새 템플릿을 추가하면 여기에 한 줄 추가 + `.ts` 파일 생성 + verification
tool에 kind config 추가.

---

## 템플릿 → agent 작성물 흐름

Reverser가 `reverser-research.md`를 생성하는 full flow:

```
1. omp_get_template("reverser-research-en")
   → { ok: true, kind: "...", template: "<전체 template string>" }

2. Agent reads the template string:
   - "## Rules for filling this template" section → memorizes rules
   - "## Skeleton" code block → identifies required sections + placeholders

3. Agent fills the skeleton:
   - Substitutes each <placeholder> with actual content from in-memory
     analysis records
   - Preserves section order and headings exactly

4. Agent calls `write` tool:
   → <challenge_dir>/.omp/artifacts/reverser-research.md

5. Agent calls omp_verify_template_output("reverser-research-en", <content>)
   → Tool parses template to extract required sections
   → Tool runs 5 checks on content:
      - Required sections present
      - No unfilled <...> placeholders
      - No forbidden English vuln words
      - (KO only) No forbidden Korean words
      - (KO only) No Korean translations of technical terms
   → Returns { ok: true } or { ok: false, violations: [...] }

6a. If ok → proceed to step 7
6b. If violations (retry 1): Agent reads violations, fixes content,
    calls `write` again, then re-verifies (retry 2: same, retry 3: same).
    Max 2 retries.
6c. After 2 failed retries: prepend
    "(VERIFICATION FAILED — STRUCTURAL ISSUES REMAIN)" to artifact header,
    record violations in journal, continue (do not block indefinitely).

7. Agent moves to next step (KO report or omp_patch_state).
```

Step 5~6의 retry loop가 핵심 안전망입니다. LLM이 쉽게 놓치는 failure
mode — placeholder 미치환, 섹션 누락, 금지어 slip — 을 mechanical하게
catch합니다.

---

## 새 템플릿 추가하려면?

### 1. Template 파일 생성

`src/templates/<kind-name>.ts` 생성:

```ts
export const myNewTemplate = `# Template: <kind-name>

## Rules for filling this template

- <rule 1>
- <rule 2>
- ...

## Skeleton

\\\`\\\`\\\`markdown
# <Artifact Title>

## <Section 1>

<placeholder 1>

## <Section 2>

<placeholder 2>
\\\`\\\`\\\`
`
```

### 2. Registry 등록

`src/templates/index.ts`에 import + map entry 추가:

```ts
import { myNewTemplate } from "./my-new-template"

export const OMP_TEMPLATES = {
  "reverser-research-en": reverserResearchEnTemplate,
  "reverser-research-ko": reverserResearchKoTemplate,
  "my-new-kind": myNewTemplate,  // ← 추가
} as const
```

### 3. Verification config 추가

`src/tools/omp-verify-template-output.ts`의 `KIND_CONFIGS`에 entry 추가:

```ts
const KIND_CONFIGS: Record<string, TemplateConfig> = {
  // ...
  "my-new-kind": {
    extractRequiredSections: true,
    checkForbiddenEn: true,
    checkForbiddenKo: false,          // 한국어 포함 아니면 false
    checkKoTechnicalTranslations: false,
    checkUnfilledPlaceholders: true,
  },
}
```

**중요:** VulnHunter/Exploiter 템플릿을 만들 때는 **forbidden words
list를 customize해야** 합니다. 예를 들어 VulnHunter는 exploit 언어를
**허용**해야 하므로 `checkForbiddenEn`을 false로 하거나 다른 forbidden
list를 별도 정의.

현재 구현은 단일 `FORBIDDEN_EN_WORDS` 상수를 씁니다. 더 정교한 per-kind
forbidden list가 필요해지면 `KIND_CONFIGS` entry에 `forbiddenEnWords:
string[]` 같은 필드를 추가하는 방향으로 확장.

### 4. Agent prompt에서 호출

Agent의 required sequence에 template 사용 단계 명시:

```
N. Call omp_get_template("my-new-kind") → read rules, fill skeleton
N+1. write → <path>
N+2. Call omp_verify_template_output("my-new-kind", <content>)
N+3. Retry on violations (max 2)
```

### 5. 빌드 & 재시작

```bash
bun run typecheck
bun test
bun run build:plugin
# omp 재시작
```

---

## Verification tool의 한계

`omp_verify_template_output`은 **mechanical check만** 수행합니다. 다음은
**하지 않는 것**:

- **Semantic correctness** — "purpose paragraph가 pseudocode와 일치하는가"
  같은 의미 검증은 Reverser의 Pass B self-review가 담당
- **Length check** — 사용자 결정으로 제외 ("프로그램이 커지면 800단어로
  부족할 수 있음"). 템플릿 rules에서 soft guideline으로만 언급.
- **Subjective tone check** — "first-person이 자연스러운가" 같은 문체 판단
- **Korean grammar / 자연스러움** — 번역체인지 아닌지는 LLM 자체가 판단
  (템플릿 rules에 "자연스러운 한국어" 지침 명시, verification은 enforce 안 함)

이 한계는 의도적입니다. Mechanical check는 **결정적**이어야 하고,
semantic/subjective 판단은 **LLM의 일**이라 agent prompt와 self-review로
handle.

---

## 향후 추가될 템플릿 (예정)

> 3-agent exploit pipeline redesign (2026-04-17) 반영.

| 템플릿 kind | 사용 agent | 목적 |
|---|---|---|
| `vulnhunter-candidates` | VulnHunter (T10) | Vulnerability candidate 랭킹 표 (primitive 태그, libc range, confidence) |
| `vulnhunter-candidates-ko` | VulnHunter | 한국어 버전 |
| `strategist-plan` | StrategyAgent (T14) | Exploit step plan (각 step의 goal, expected result, technique 참조) |
| `strategist-plan-ko` | StrategyAgent | 한국어 버전 |
| `exploiter-stage-report` | Exploiter (T16) | Stage execution 결과 (pass/fail, observed state, leak captures, pwno-mcp 관찰 결과) |
| `exploiter-stage-report-ko` | Exploiter | 한국어 버전 |

> ~~`verifier-stage-report`~~ — Verifier가 Exploiter에 통합됨 (2026-04-17).
> `exploiter-stage-report`가 대체.

이들은 해당 agent 구현 시점에 추가. 지금은 `reverser-research-{en,ko}`만
존재.

---

## 관련 파일 요약

| 파일 | 역할 |
|---|---|
| `src/templates/index.ts` | Template registry + `getOmpTemplate` / `listOmpTemplateKinds` |
| `src/templates/reverser-research-en.ts` | 영문 연구 보고서 템플릿 |
| `src/templates/reverser-research-ko.ts` | 한국어 연구 보고서 템플릿 |
| `src/tools/omp-get-template.ts` | Template 로드 tool |
| `src/tools/omp-verify-template-output.ts` | 검증 tool + per-kind config + forbidden lists |
| `.omc/specs/deep-interview-reverser-redesign.md` (Addendum #3) | 템플릿 시스템 설계 근거 |

다음 문서에서 **개발 환경 / 빌드 / 테스트 워크플로우**를 다룹니다 →
[development.md](development.md).
