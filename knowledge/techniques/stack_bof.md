# stack_bof — Stack Buffer Overflow

## 동작 원리

Stack에 할당된 고정 크기 buffer에 초과 입력이 들어가면 인접한 stack 영역(local variables, saved rbp, return address)을 덮어쓸 수 있다. x86_64 SysV ABI에서 함수 prologue는 `push rbp; mov rbp, rsp; sub rsp, N` 패턴이고, stack은 아래로 자란다:

```
높은 주소
┌────────────────────┐
│ return address     │  ← rbp + 8
├────────────────────┤
│ saved rbp          │  ← rbp
├────────────────────┤
│ (canary)           │  ← rbp - 8 (있을 때)
├────────────────────┤
│ local vars / buf   │  ← rbp - N
└────────────────────┘
낮은 주소
```

Buffer에 overflow가 발생하면 위로(높은 주소 방향) canary → saved rbp → return address 순서로 덮인다.

## Reverser output에서 찾을 패턴

- `read(0, buf, size)` where `size > buf 크기` (Reverser의 stack frame에서 buffer 크기와 read size 비교)
- `gets(buf)` — 길이 제한 없음, 무조건 overflow 가능
- `scanf("%s", buf)` — 길이 제한 없음
- `strcpy(buf, user_controlled)` — source 길이가 buf 초과 가능
- Reverser의 stack frame distances: `buffer → canary`, `buffer → saved_rbp`, `buffer → return_address`

## Exploit 절차

1. **Offset 파악:** Reverser의 stack frame 정보 또는 cyclic pattern으로 buffer 시작부터 return address까지의 distance 계산
2. **Payload 구성:** `padding (offset bytes) + target_address`
3. **Canary 처리:** canary가 있으면 먼저 leak (fmt_string_read 등) 후 canary 자리에 올바른 값 삽입
4. **Return address 결정:** ret2win, ROP chain, shellcode 중 상황에 맞게 선택

## 주의점

- **Canary:** 덮으면 `__stack_chk_fail` 호출로 crash. 반드시 leak 후 보존하거나, canary가 없는지 확인
- **Stack alignment:** x86_64에서 `system()` 등 libc 함수 호출 시 RSP가 16-byte aligned여야 함. padding에 `ret` gadget 하나 추가로 해결
- **PIE:** binary에 PIE가 켜져 있으면 binary 내부 주소도 randomized. binary base leak 필요
- **NX:** stack이 non-executable이면 shellcode 직접 실행 불가 → ROP 필요

## StrategyAgent 참고: typical step plan

```
Step 1: Offset 확인 (padding size → return address)
Step 2: Canary 처리 (없으면 skip, 있으면 leak 방법 탐색)
Step 3: Return address target 결정 (ret2win? ROP?)
Step 4: (ROP인 경우) libc leak → libc base 계산
Step 5: Final payload 구성 → shell/flag
```
