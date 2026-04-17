# ret2win — Return to Win Function

## 동작 원리

Binary 안에 exploit의 최종 목표를 달성하는 함수("win function")가 이미 존재할 때, return address를 해당 함수 주소로 덮어서 호출하는 기법. CTF의 Lv1 문제에서 가장 흔하다.

Win function의 전형적 패턴:
- `system("/bin/sh")` 호출
- `execve("/bin/sh", NULL, NULL)` 호출
- `open("flag.txt") → read → write` 패턴
- `puts(flag_string)` 등 flag 직접 출력

## Reverser output에서 찾을 패턴

- Reverser의 Function Map에서 `system`, `execve` 호출이 있는 non-main 함수
- "flag", "shell", "win", "backdoor", "secret" 등의 이름이 붙은 함수 (Reverser가 rename했을 수 있음)
- 직접 호출되지 않는 함수 (main의 control flow에서 도달 불가능)
- `cat flag*`, `/bin/sh`, `flag.txt` 등 문자열을 참조하는 함수

## Exploit 절차

1. **Win function 주소 확인:** Reverser output의 Function Map에서 획득. PIE 꺼져 있으면 고정 주소.
2. **RIP control 획득:** stack_bof 등으로 return address 장악
3. **Payload:** `padding + win_function_address`
4. **인자 전달 (필요 시):** win function이 인자를 요구하면 (`win(0xdeadbeef)` 등) ROP로 rdi에 값 세팅: `pop_rdi_ret + arg + win_addr`

## 주의점

- **Stack alignment:** `system()` 호출 시 16-byte alignment 필요. `ret` gadget 하나 선행 삽입
- **PIE enabled:** binary base leak이 필요. ret2win 단독으로는 불가 → fmt_string_read 등으로 먼저 leak
- **Win function의 인자:** 일부 문제에서 win function은 특정 인자 값을 체크. ROP로 rdi/rsi 세팅 필요
- **Win function 주소가 `\x0a`, `\x00` 포함:** gets/scanf 등 입력 함수가 이 바이트에서 끊김 → 다른 path 필요

## StrategyAgent 참고: typical step plan

```
Step 1: Win function 주소 확인
Step 2: RIP control 획득 (stack_bof offset 확인)
Step 3: (인자 필요 시) pop_rdi gadget 확인
Step 4: Payload 구성 → win function 호출
```
