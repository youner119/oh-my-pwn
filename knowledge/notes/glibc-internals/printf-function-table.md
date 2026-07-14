---
title: printf custom conversion table 하이재킹 (House of Husk)
tags: [glibc, printf, vfprintf, code-execution, hook-removal-era, house-of-husk]
applies_to_glibc: ">= 2.27"   # 2.34+ 에서 __free_hook 대체재로 특히 유용. 2.41 까지 유효.
last_updated: 2026-07-14
---

# printf custom conversion table 하이재킹 (House of Husk)

glibc 는 `%Y` 같은 **사용자 정의 printf 변환 지정자**를 등록할 수 있게
`register_printf_specifier` / `register_printf_function` API 를 제공한다.
등록 정보는 libc 내부의 **전역 함수 포인터 테이블**에 저장되는데, 이
테이블 포인터를 조작하면 *평범한 `printf` 호출 한 번*으로 제어 흐름을
가로챌 수 있다. glibc 2.34 에서 `__malloc_hook`/`__free_hook` 이 제거된
뒤, 단일 libc write primitive 로 RIP 를 잡는 몇 안 되는 깔끔한 data
타겟 중 하나다. 이 delivery 를 **House of Husk** 라 부른다.

본 note 는 *printf table 메커니즘 그 자체* (재사용 가능한 insight) 에
집중한다. heap primitive (unsorted bin attack / largebin attack) 의
raw 절차는 vendor `knowledge/ctf-pwn/heap-techniques.md` +
`knowledge/how2heap/` 참조 (중복하지 않음).

---

## 1. 관련 전역 (모두 libc, 초기값 NULL)

```
__printf_function_table   ← 출력 콜백 테이블 (spec char 로 인덱싱)
__printf_arginfo_table    ← 인자 정보 콜백 테이블 (spec char 로 인덱싱)
__printf_modifier_table   ← modifier 파싱 테이블
__printf_va_arg_table     ← va_arg 타입 테이블
```

`__register_printf_specifier` (`stdio-common/reg-printf.c`) 최초 호출 시
`calloc(UCHAR_MAX + 1, sizeof(void*) * 2)` 로 **256-entry** 테이블을
할당하고:

```c
__printf_function_table[spec] = converter;
__printf_arginfo_table[spec]  = arginfo;
```

를 채운다. spec 은 변환 문자 (`'s' == 0x73`), 각 entry 는 8-byte 포인터.

## 2. 트리거 게이트 (`vfprintf-internal.c`)

`__vfprintf_internal` 진입 직후, 아래 세 테이블 중 **하나라도 non-NULL**
이면 fast path 를 버리고 `do_positional` (느린 콜백 경로) 로 점프한다:

```c
if (__glibc_unlikely (__printf_function_table != NULL
                      || __printf_modifier_table != NULL
                      || __printf_va_arg_table != NULL))
  goto do_positional;
```

> ⚠️ 게이트 조건에 `__printf_arginfo_table` 은 **없다**. 게이트를 열려면
> `__printf_function_table` (또는 modifier/va_arg) 를 non-NULL 로 만든다.

## 3. 콜백 호출부 (함수 포인터 2군데)

### 3-1. arginfo 콜백 — parse 단계, **먼저** 실행됨 (`printf-parsemb.c`)

`__parse_one_specmb` 안에서, `__printf_function_table != NULL` 이면
built-in 처리를 건너뛰고 arginfo 테이블을 인덱싱한다:

```c
if (__builtin_expect (__printf_function_table == NULL, 1)
    || spec->info.spec > UCHAR_MAX
    || __printf_arginfo_table[spec->info.spec] == NULL          // (a) NULL 가드
    || (int) (spec->ndata_args =                                // (b) 함수 포인터 호출
        (*__printf_arginfo_table[spec->info.spec])
          (&spec->info, 1, &spec->data_arg_type, &spec->size)) < 0)
  { /* built-in 지정자 처리 */ }
```

- **인덱스**: `spec->info.spec` (변환 문자값, 0–255).
- **호출 인자**: `(&spec->info, 1, &spec->data_arg_type, &spec->size)`
  → **rdi = &spec->info** (vfprintf 스택 내부 주소).
- 가드 (a) 때문에 `__printf_arginfo_table` 자체 + `[spec]` entry 가
  **반드시 non-NULL** 이어야 여기 도달. arginfo_table 이 NULL 포인터인데
  게이트만 열려 있으면 `NULL[spec]` 역참조로 **crash**.

이 arginfo 콜백이 **format 파싱 중 가장 먼저** 불리므로, 실전 RIP 하이재킹
1순위 타겟이다.

### 3-2. function 콜백 — 출력 단계 (`printf_positional`)

```c
function_done = __printf_function_table[(size_t) spec]
                  (s, &specs[nspecs_done].info, ptr);
```

- **호출 인자**: `(s, &info, ptr)` → **rdi = s (FILE* 스트림)**.
- arginfo 경로에서 이미 죽지 않았다면 여기까지 옴.

## 4. 콜백 시그니처 (`stdio-common/printf.h`)

```c
/* function table entry */
typedef int printf_function (FILE *__stream,
                             const struct printf_info *__info,
                             const void *const *__args);

/* arginfo table entry */
typedef int printf_arginfo_size_function (const struct printf_info *__info,
                                          size_t __n,
                                          int *__argtypes, int *__size);
```

`struct printf_info` 앞부분: `int prec; int width; wchar_t spec; ...`.
→ arginfo 콜백의 rdi(`&info`) 가 가리키는 첫 8 byte = `{prec, width}`.
프로그램의 format string 을 제어할 수 있으면 (`%<width>.<prec>X`) 이
값을 어느 정도 셋업할 수 있으나, 고전 House of Husk 는 대상 프로그램의
자기 `printf("%s", ...)` 를 트리거로 쓰므로 rdi 내용은 대개 고정.

## 5. 익스플로잇 요건 (delivery 무관)

1. **libc leak** — 테이블이 libc 안에 있으므로 base 필요.
2. **두 전역에 대한 write primitive**:
   - `__printf_function_table` ← non-NULL (게이트 오픈용). fake 테이블
     주소여도 되고, arginfo 와 같은 영역을 가리켜도 됨.
   - `__printf_arginfo_table` ← 실제로 `[spec]` 에 타겟 포인터가 박힌
     fake 테이블 주소.
3. **트리거가 되는 후속 printf** — 대상 프로그램이 실제로 **그 spec
   문자를 쓰는** printf/fprintf 를 실행해야 함. `%s`(0x73) 가 가장 흔함.
   아무 printf 나 되는 게 아니라 인덱스가 맞아야 한다.

### 고전 delivery — House of Husk

heap-only 시나리오에서 위 write 를 만드는 전형 체인:

1. **unsorted bin attack** 으로 `global_max_fast` 를 큰 값으로 덮음
   → 거의 모든 크기의 free 가 fastbin 취급 → libc 영역으로의 write 확보.
2. 알맞게 크기 계산한 chunk 를 free/allocate 해서
   `__printf_function_table` / `__printf_arginfo_table` 에 heap 포인터를
   심음 (fake 테이블 = heap 상의 조작된 영역, `[spec]` 자리에 one_gadget).
3. 이후 프로그램의 `printf` 가 그 spec 을 만나면 → RIP 획득.

largebin attack (`bk_nextsize → target - 0x20`) 으로 두 전역에 직접
포인터를 쓰는 변형도 흔하다. **핵심 insight = "printf table 2개 + 후속
printf"** 이고, 위 heap 기법은 그 write 를 얻는 여러 통로 중 하나일 뿐.

## 6. Gotcha 체크리스트

- **두 테이블 다 유효해야 함.** function_table 만 non-NULL 로 열고
  arginfo_table 을 NULL 로 두면 parse 단계에서 `NULL[spec]` crash.
- **spec 문자 일치.** 심은 인덱스 = 트리거 printf 가 쓰는 변환 문자.
  `%s` 노릴 거면 `[0x73]`, `%d` 면 `[0x64]`.
- **rdi 는 one_gadget 제약을 좌우.** arginfo 경로 rdi=&info(스택),
  function 경로 rdi=FILE*. 맞는 one_gadget 이 없으면 stack pivot /
  `system` 셋업 필요.
- **버전.** 2.27–2.35 는 위 코드 그대로. 2.37+ 는 내부가
  `Xprintf_buffer` / `__printf_function_invoke` 로 리팩터됐지만 테이블
  하이재킹은 그대로 유효 (오프셋만 재확인). 2.41 까지 exploitable 확인됨.
- **왜 hook-removal era 에 뜨나.** 2.34+ 에서 `__malloc_hook`/`__free_hook`
  제거 → 단일 write 로 RIP 잡는 data 타겟이 귀해짐. printf table 은
  FSOP(`_IO_str_overflow` 등) / exit handler 조작과 나란한 대안.

## 7. 참고

- glibc source: `stdio-common/vfprintf-internal.c` (게이트 + `printf_positional`),
  `stdio-common/printf-parsemb.c` (arginfo 호출), `stdio-common/reg-printf.c`
  (테이블 할당), `stdio-common/printf.h` (시그니처 + `struct printf_info`).
- GNU libc manual — "Customizing Printf".
- Maxwell Dulin, "House of Husk - In Depth Explanation".
- 4xura, "House of Husk".
- vendor: `knowledge/ctf-pwn/heap-techniques.md`, `knowledge/ctf-pwn/format-string.md`,
  `knowledge/how2heap/` (unsorted bin / largebin attack raw).
