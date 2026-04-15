/**
 * Reverser research report template (Korean).
 *
 * Served by the `omp_get_template` tool. Same two-section structure as
 * the English template (`## Rules for filling this template` followed
 * by `## Skeleton`), but with Korean-specific language rules and a
 * parallel Korean forbidden-words list.
 *
 * The KO template is a **full translation** of the English report, not
 * a shortened summary. Technical terms stay in English per project
 * convention (`stack`, `heap`, `canary`, `read`, `printf`, etc.).
 */

export const reverserResearchKoTemplate = `# Template: reverser-research-ko

## Rules for filling this template

한국어 버전 research 보고서를 작성할 때 따라야 할 규칙. 이는
**template-local 규칙**으로 이 artifact에만 적용된다. System prompt의
cross-cutting 규칙 (neutrality, forbidden-words list, state management,
type inference 등) 은 이 규칙 위에 여전히 적용된다.

- **Audience:** Korean-speaking pwn operator (프로젝트의 primary user,
  see \`CLAUDE.md\`). English 버전과 동일한 내용을 한국어로 자연스럽게.
- **Tone:** 자연스러운 Korean prose. "번역체" 느낌 피할 것 — Korean
  sentence rhythm, particles, connectors 활용. First-person 서술
  ("나는 ~를 관찰했다", "~로 rename했다") 허용.
- **Length:** hard limit 없음. Korean은 영어보다 denser라 동일한
  내용이 더 짧아질 수 있음. 이해 전달에 필요한 만큼만 쓴다.
- **Full translation, not summary:** English 버전과 동일한 섹션 구조,
  동일한 순서. 각 섹션을 자연스러운 한국어로 풀어 쓴다. 줄이거나
  일부만 다루지 말 것.
- **Do NOT re-explain pwn basics.** User는 숙련된 pwn operator다.
  "canary는 stack 보호를 위한 값인데..." 같은 문장은 condescending
  noise — skip.

### Technical terms — keep in English

다음 용어들은 한국어로 번역하지 말 것. 그대로 영문 유지:

- **ghidra-mcp tool names:** \`rename_function\`, \`batch_set_variable_types\`,
  \`decompile_function\`, \`batch_set_comments\`, 등
- **C / libc function names:** \`read\`, \`printf\`, \`setvbuf\`, \`malloc\`,
  \`free\`, \`memcpy\`, \`strcpy\`, 등
- **Binary / mitigations 어휘:** \`stack\`, \`heap\`, \`canary\`, \`NX\`,
  \`PIE\`, \`RELRO\`, \`rbp\`, \`rsp\`, \`PLT\`, \`GOT\`, \`libc\`, \`frame\`
- **Numeric literals:** \`0xba\`, \`0xa0\`, \`[rbp-0xb8]\`
- **Variable / function names (after rename):** \`input_buf\`,
  \`stack_canary\`, \`run_two_round_input_echo\`, \`disable_stdio_buffering\`

중요한 확인: 다음 단어들은 verification tool이 **번역 위반**으로 잡는다.
KO 보고서에 이 단어들이 등장하면 해당 영문 기술용어를 번역해버린
것이므로 verification이 실패한다:

- \`스택\` → \`stack\`으로 돌릴 것
- \`힙\` → \`heap\`
- \`캐나리\` / \`카나리\` → \`canary\`
- \`버퍼\` → \`buffer\`

### Forbidden Korean words (parallel to English forbidden list)

System prompt의 English forbidden-words list와 병행하는 Korean forbidden
list. KO 보고서에 다음 단어들이 한 번이라도 등장하면 verification 실패.

**금지 명사:** \`취약점\`, \`취약성\`, \`익스플로잇\`, \`오버플로우\`,
\`유출\`, \`누출\`, \`악용\`, \`악용 가능\`.

**금지 서술:** "~할 수 있다" (공격 가능성 맥락에서), "가능성이 있다",
"의심된다", "위험하다", "안전하지 않다", "악용 가능", "악용할 수 있는".

**금지 연결어:** "~로 인해 ~가 발생한다" (취약점 원인-결과 연결),
"따라서 ~가 가능하다", "결과적으로 exploit", "~을 의미한다" (취약점을
지시하는 맥락).

**허용되는 사실 서술:** "0xba 바이트를 0xa0 크기 stack buffer에 읽는다",
"\`stack_canary\`는 \`[rbp-0x10]\`에 저장된다", "\`input_buf\`에서
\`stack_canary\`까지의 거리는 0xa8 바이트다". 숫자, 구조, 관측된 호출
관계는 전부 허용.

### Dual self-check

문장 하나를 쓰기 전에 **English forbidden list** (system prompt) AND
**Korean forbidden list** (위) 양쪽을 머릿속으로 대조한다. 어느 한쪽에
걸리는 단어가 있으면 해당 문장을 삭제하고 중립 관측으로 rewrite.
그래도 안 되면 그 문장은 판단이 섞인 것이니 drop.

### Heading convention

\`## Executive summary (요약)\` 형식으로 **English section name + optional
Korean parenthetical**. 이렇게 하면 English 버전과 cross-reference가
쉬워진다 — Korean 버전 읽는 사람이 English section name으로 search 가능.
본문은 자연스러운 한국어로 유지.

### Placeholders

Skeleton의 \`<...>\` marker를 전부 실제 content로 치환한다. 미치환
placeholder가 남으면 verification 실패.

## Skeleton

아래 markdown block이 skeleton. \`\\\`\\\`\\\`markdown\` fence는 templage 파일의
frame일 뿐이므로 출력하지 않고, 내부 body만 verbatim으로 emit하되
\`<...>\`는 실제 content로 치환한다.

\\\`\\\`\\\`markdown
# Reverser Research Report: <binary_basename> (한국어)

_Generated: <ISO timestamp> | Binary sha: <sha256> | Analysis roots: <comma-separated analysis roots, e.g. main, _init, _fini, _start>_

## Executive summary (요약)

<1-2 문단, 자연스러운 한국어 prose. "이게 뭘 하는 program인가"를
사람이 이해할 수 있게. program type (menu-driven / server / one-shot /
trigger-based), I/O model (stdin / socket / file), 주요 state (global
buffer, heap array, state machine mode 등) 언급. 중립 사실만.>

## Analysis approach (분석 접근)

<2-3 문장으로 어떤 root에서 BFS 시작했는지, depth 얼마 썼는지,
analysis set에 user function 몇 개가 들어갔는지, 어떤 ghidra-mcp tool을
호출했는지 서술. 순수 process narrative.>

## What each function does (함수별 역할)

<main부터 call order로 user function을 prose로 풀어 설명. 각 함수당
2-4 문장. rename된 이름 사용. 다른 함수와의 관계, 건드리는 state 언급.
program 이해에 중요한 함수에 집중. function map 재복제 금지 — 그건
reverser-analysis.md에 있음.>

## Types I applied (적용한 타입)

<타입 refinement 내역을 prose로. 관찰된 pattern + 선택한 타입 이유
1-2 문장씩. 0개 적용했으면 이 섹션 생략.>

## Data entry points (입력 진입점)

<공격자 제어 데이터가 어디서 program에 들어오는지. 어느 함수가
user-input sink (\`read\`, \`recv\`, \`fgets\`, \`scanf\` 등)를 호출하고
어느 buffer나 global에 데이터가 들어가는지. 중립 서술 — 진입점만,
데이터로 뭘 할 수 있는지는 언급하지 말 것.>

## Stack frames of interest (주요 stack frame)

<함수의 stack frame에 의미 있는 local이 있는 경우만. 1-3개 함수를
prose로 요약. 정확한 offset과 distance는 structured artifact의
per-function "Stack frame" subsection 참조 포인팅. 표 복제 금지.
non-trivial stack frame이 하나도 없으면 이 섹션 생략.>

## Handoff notes (인수인계)

<마무리 1-2 문장. VulnHunter와 Exploiter가 다음에 어느 artifact를
읽어야 하는지 포인팅 (\`reverser-analysis.md\`). 그들의 작업에 특히
관련된 structural 사실 하나 언급 가능. 어떤 취약점을 보라고 제안하지
말 것.>
\\\`\\\`\\\`
`
