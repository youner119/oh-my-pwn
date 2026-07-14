# notes/glibc-internals/

glibc 내부 자료구조 / 전역 상태를 노린 exploitation 타겟 정리.
`__malloc_hook`/`__free_hook` 제거 (2.34+) 이후 단일 write 로 RIP 를
잡는 data 타겟 (printf table / FSOP / exit handler 등) 이 주 대상.

## Entries

- [printf-function-table.md](printf-function-table.md) — printf custom
  conversion table (`__printf_function_table` / `__printf_arginfo_table`)
  하이재킹 = House of Husk. 트리거 게이트 + arginfo/function 콜백 호출부
  + delivery 요건 + gotcha.

## Related raw material

- vendor: `ctf-pwn/heap-techniques.md`, `ctf-pwn/format-string.md`, `ctf-pwn/heap-fsop.md`
- vendor: `how2heap/` (unsorted bin / largebin attack raw source)
