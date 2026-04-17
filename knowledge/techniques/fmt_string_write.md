# fmt_string_write — Format String Arbitrary Write

## 동작 원리

`%n` format specifier는 "지금까지 출력된 바이트 수"를 인자가 가리키는 메모리에 쓴다. 이를 이용해 임의 주소에 임의 값을 쓸 수 있다.

Variants:
- `%n` — 4 bytes (int)
- `%hn` — 2 bytes (short)
- `%hhn` — 1 byte (char)
- `%ln` — 8 bytes (long, 64-bit)

원하는 값을 쓰려면 `%Nc` (N개 문자 출력)로 출력 카운트를 조정한 후 `%hhn`으로 1 byte씩 쓰는 것이 일반적.

## Reverser output에서 찾을 패턴

- fmt_string_read와 동일: `printf(user_buf)` 패턴
- 추가 조건: format string을 **여러 번 호출**할 수 있으면 유리 (한 번에 여러 byte write가 어려우므로)
- Loop 안에서 printf가 호출되는 경우 (menu-driven program)

## Exploit 절차

1. **Format string offset 확인** (fmt_string_read와 동일)
2. **Write target 결정:**
   - GOT entry (partial RELRO): 함수 GOT를 system/one_gadget 주소로 덮기
   - `__free_hook` / `__malloc_hook` (glibc < 2.34): hook을 system/one_gadget으로
   - Return address on stack: 직접 return address 덮기
   - `.fini_array`: 프로그램 종료 시 호출되는 함수 배열
3. **Write value 결정:** target에 쓸 주소 (libc 함수, one_gadget 등). fmt_string_read로 미리 leak 필요.
4. **Payload 구성:** pwntools의 `fmtstr_payload(offset, {target: value})` 활용 권장
5. **Trigger:** write 후 overwritten 함수를 호출하거나 (GOT), free/malloc을 trigger (hook)

## 주의점

- **Full RELRO:** GOT가 read-only → GOT overwrite 불가. `__free_hook`, stack return address, `.fini_array` 등 다른 target 필요
- **glibc >= 2.34:** `__malloc_hook`, `__free_hook` 제거됨 → stdout FILE struct overwrite, stack return address, `.fini_array` 등으로 전환
- **Write 크기:** 한 번에 큰 값을 쓰려면 `%Nc`에서 N이 매우 커져서 출력이 느림. `%hhn`으로 1 byte씩 분할이 일반적
- **pwntools fmtstr_payload:** offset만 정확하면 payload 자동 생성. 단, 출력 길이 제한이 있으면 수동 최적화 필요
- **Stack 주소 변동:** write target이 stack 주소이면 ASLR로 매번 바뀜 → 같은 connection에서 leak 후 사용

## StrategyAgent 참고: typical step plan

```
Step 1: Format string offset 파악
Step 2: (fmt_string_read로) libc base, target 주소 leak
Step 3: Write target 결정 (GOT? hook? return address?)
Step 4: fmtstr_payload로 write payload 구성
Step 5: Payload 전송 → overwritten target trigger → shell
```
