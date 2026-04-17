# tcache_poison — Tcache Free List Poisoning

## 동작 원리

glibc >= 2.26에서 도입된 tcache (thread-local cache)는 per-thread free list로, 작은 크기의 chunk를 빠르게 재할당한다. tcache bin은 singly-linked list이고, freed chunk의 `fd` (next) pointer가 다음 free chunk를 가리킨다.

이 `fd` pointer를 공격자가 제어하는 값으로 덮으면, 이후 malloc이 해당 주소를 반환한다.

```
정상 tcache bin:     chunk_A → chunk_B → NULL
poisoned:           chunk_A → target_addr → ???
                    malloc() → chunk_A
                    malloc() → target_addr  ← 임의 주소에 chunk 할당!
```

glibc >= 2.34의 safe-linking:
```
stored_fd = real_fd ^ (chunk_addr >> 12)
```
heap base를 알면 역산 가능.

## Reverser output에서 찾을 패턴

- **UAF (Use-After-Free):** free 후 동일 pointer로 read/write. Reverser에서 free() 호출 후 같은 pointer가 다시 사용되는 패턴
- **Heap overflow:** malloc chunk에 초과 쓰기 → 인접 freed chunk의 fd 덮기
- **Double free:** 같은 chunk를 두 번 free (glibc >= 2.29에서 tcache key 검사로 탐지됨, 하지만 우회 가능)
- Menu-driven program: allocate / edit / delete / show 기능이 있는 전형적 heap 문제 구조

## Exploit 절차

1. **Heap 레이아웃 준비:** 필요한 크기의 chunk들을 allocate/free하여 tcache bin 상태 구성
2. **fd pointer 조작:**
   - UAF: freed chunk에 write로 fd를 target address로 덮기
   - Heap overflow: 인접 freed chunk의 fd 영역까지 overflow
   - Double free: 같은 chunk를 두 번 free → allocate하면서 fd를 target으로 설정
3. **Safe-linking 처리 (glibc >= 2.34):**
   - Heap base leak 필요 (보통 unsorted bin leak 또는 tcache fd leak으로)
   - `forged_fd = target_addr ^ (chunk_addr >> 12)`
4. **malloc → target address 획득:** poisoned bin에서 두 번 malloc하면 target address에 chunk 할당
5. **Write to target:** 할당된 영역에 원하는 값 쓰기

## Write targets

| Target | 조건 | 효과 |
|---|---|---|
| `__free_hook` | glibc < 2.34 | free() 호출 시 hook 함수 실행 |
| `__malloc_hook` | glibc < 2.34 | malloc() 호출 시 hook 함수 실행 |
| stdout `_IO_2_1_stdout_` | any glibc | FILE struct 조작으로 arbitrary read/write |
| `.got.plt` entry | partial RELRO | 특정 함수 호출 redirect |
| Stack return address | any | ROP chain 설치 (stack 주소 leak 필요) |

## 주의점

- **tcache count:** glibc >= 2.29에서 tcache에 `count` 필드 추가. 0이면 tcache에서 할당 안 됨. double free 방지 목적이지만 count를 조작하면 우회 가능
- **tcache key:** glibc >= 2.29에서 freed chunk에 key를 기록해서 double free 탐지. key를 덮어서 우회 가능
- **Safe-linking (glibc >= 2.34):** fd가 XOR 암호화됨. heap base의 상위 bits를 알아야 복호화/위조 가능. 첫 번째 tcache entry의 fd는 `0 ^ (addr >> 12)` = `addr >> 12`이므로 직접 heap base 계산 가능
- **Chunk size 검증:** target address에 할당할 때 glibc가 chunk header의 size를 검증. target 근처에 적절한 size 값이 있어야 함 (fastbin에서 더 엄격, tcache에서는 느슨)
- **Alignment:** x86_64에서 malloc은 16-byte aligned 주소 반환. target address도 aligned여야 함

## StrategyAgent 참고: typical step plan

```
Step 1: Heap 레이아웃 구성 (alloc/free 순서 결정)
Step 2: Heap base leak (unsorted bin → libc leak, tcache fd → heap base)
Step 3: fd pointer 조작 (UAF write 또는 overflow)
Step 4: (glibc >= 2.34) Safe-linking XOR 계산
Step 5: malloc → target address 획득
Step 6: Target에 원하는 값 write (system addr, one_gadget 등)
Step 7: Trigger → shell
```
