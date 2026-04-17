# TechniqueKB — Exploitation Technique Catalog

> VulnHunter/StrategyAgent가 빠르게 스캔하는 카탈로그.
> 자체 분석으로 후보를 못 찾았을 때, 또는 다음 chain을 결정할 때 참조.
> 상세 내용은 각 technique의 개별 MD 파일에 있음.

---

## stack_bof

**tags:** stack, buffer-overflow, ret-overwrite
**gives:** RIP control
**needs:** buffer input이 stack local variable에 쓰임, 입력 길이가 buffer 크기 초과 가능
**mitigations:** canary 없음 or canary leak 가능, NX/PIE 무관
**glibc:** any
**chain:** → ret2win | → ROP → ret2libc | → ROP → one_gadget | → shellcode (NX off)

> 고정 크기 stack buffer에 초과 입력 → saved rbp + return address 덮기. Reverser output에서 `read`, `gets`, `scanf("%s")`, `recv` 등이 local buffer에 쓰이고, 크기 검증이 없거나 부족한 경우.

---

## ret2win

**tags:** stack, ret-overwrite, direct-call, no-leak-needed
**gives:** arbitrary function call (보통 flag 출력 또는 shell 함수)
**needs:** RIP control (stack_bof 등), binary 안에 win function 존재
**mitigations:** PIE 없으면 주소 고정, PIE 있으면 PIE base leak 필요
**glibc:** any
**chain:** (terminal — 단독으로 exploit 완성)

> Binary 내부에 flag를 출력하거나 `system("/bin/sh")`를 호출하는 "win" function이 있을 때, return address를 해당 함수 주소로 덮는 것. PIE가 꺼져 있으면 주소가 고정이므로 leak 없이 가능. 가장 단순한 exploitation path.

---

## fmt_string_read

**tags:** format-string, leak, infoleak, stack-read
**gives:** arbitrary read (stack 값, GOT entry, libc address 등)
**needs:** user input이 printf 계열 함수의 format string으로 직접 전달됨
**mitigations:** RELRO 무관, PIE/NX 무관 (leak만 하므로)
**glibc:** any
**chain:** → libc base 계산 → fmt_string_write | → stack_bof + ROP (leak한 주소 활용)

> `printf(user_input)` 패턴. `%p`, `%x`, `%s` 등으로 stack에 있는 값을 leak. `%N$p`로 특정 offset의 값을 직접 읽기. GOT에 저장된 libc 함수 주소를 leak해서 libc base를 구하는 것이 가장 흔한 활용.

---

## fmt_string_write

**tags:** format-string, arbitrary-write, GOT-overwrite
**gives:** arbitrary write (임의 주소에 임의 값 쓰기)
**needs:** user input이 printf 계열의 format string으로 전달됨, 여러 번 호출 가능하면 유리
**mitigations:** full RELRO 시 GOT overwrite 불가 → 다른 target 필요 (stack, __malloc_hook 등)
**glibc:** any (단, __malloc_hook/__free_hook은 glibc >=2.34에서 제거됨)
**chain:** → GOT overwrite → system() | → __free_hook → one_gadget (glibc <2.34) | → return address overwrite

> `%n` specifier로 이미 출력된 바이트 수를 메모리에 쓰기. `%hhn`(1 byte), `%hn`(2 bytes), `%n`(4 bytes) 조합으로 arbitrary 값 구성. 보통 fmt_string_read로 주소를 leak한 후 수행. pwntools의 `fmtstr_payload()`가 자동 생성 지원.

---

## tcache_poison

**tags:** heap, tcache, UAF, double-free, arbitrary-alloc
**gives:** arbitrary address에 chunk 할당 (→ arbitrary write)
**needs:** UAF 또는 heap overflow로 freed chunk의 next pointer 조작 가능, tcache 사용하는 glibc
**mitigations:** safe-linking (glibc >=2.34) 시 next pointer가 XOR 암호화 → heap base leak 필요
**glibc:** >=2.26 (tcache 도입), safe-linking 없는 버전은 <=2.33
**chain:** → __free_hook overwrite (glibc <2.34) | → __malloc_hook | → stdout FILE struct | → stack pivot

> tcache free list는 singly-linked list. freed chunk의 `fd` (next) pointer를 target address로 덮으면, 이후 malloc이 target address를 반환. glibc >=2.34의 safe-linking: `next = real_next ^ (chunk_addr >> 12)`. heap base를 알면 복호화/위조 가능.
