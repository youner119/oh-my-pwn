# fmt_string_read — Format String Leak

## 동작 원리

`printf(user_input)` 처럼 사용자 입력이 format string으로 직접 전달되면, `%p`, `%x`, `%s` 등의 format specifier를 삽입해서 stack 또는 임의 메모리의 값을 읽을 수 있다.

x86_64에서 printf의 인자 전달:
- 1번째~5번째 인자: rdi(fmt), rsi, rdx, rcx, r8 (레지스터)
- 6번째 이후: stack

따라서 `%6$p`부터가 stack의 값을 읽기 시작한다. format string 자체도 stack에 있으므로, 적절한 offset에서 format string에 넣은 주소를 `%s`로 역참조할 수 있다.

## Reverser output에서 찾을 패턴

- `printf(user_buf)` — format string 인자에 user-controlled buffer가 직접 전달
- `fprintf(stderr, user_buf)` — stderr도 동일
- `snprintf(dst, size, user_buf)` — dst에 쓰이지만 leak은 side effect로 가능
- 핵심: format string 위치에 `"%s"` 같은 constant가 아닌 variable이 오는 것

## Exploit 절차

1. **Format string offset 파악:** `AAAA%p.%p.%p...` 전송 → 출력에서 `0x4141414141414141`이 나오는 위치가 format string의 stack offset
2. **Stack leak:** `%N$p`로 stack 위의 값들 읽기. 유용한 targets:
   - libc 함수 return address (→ libc base 계산)
   - Canary 값 (→ stack_bof에서 canary bypass)
   - PIE binary 주소 (→ PIE base 계산)
   - Heap pointer (→ heap base 계산)
3. **Arbitrary read:** format string offset을 알면, `%N$s` + target address를 payload에 포함시켜 해당 주소의 문자열을 읽기
4. **GOT leak:** GOT entry 주소를 넣고 `%s`로 읽으면 해당 함수의 실제 libc 주소 획득

## 주의점

- **Null byte in address:** `%s`는 null에서 멈춤. 주소에 `\x00`이 포함되면 read가 잘릴 수 있음 → `%p`로 stack에 이미 있는 pointer를 읽는 게 더 안전
- **ASLR:** 매 실행마다 주소가 바뀌므로 leak은 같은 실행(connection) 내에서 사용해야 함
- **출력 길이 제한:** 일부 문제에서 출력 길이를 제한. `%p`보다 `%lx`가 짧을 수 있음
- **Format string 한 번만 가능:** 함수가 한 번만 호출되면 leak + exploit을 한 payload에 담아야 할 수 있음 → fmt_string_write와 조합

## StrategyAgent 참고: typical step plan

```
Step 1: Format string offset 파악 (%p 반복으로 스캔)
Step 2: Stack에서 유용한 값 leak (libc ret addr, canary, PIE addr)
Step 3: Leak된 값으로 base 주소 계산 (libc_base = leaked - known_offset)
Step 4: (다음 technique으로 전달) → fmt_string_write, stack_bof + ROP 등
```
