# notes/lua/

Lua 언어 / VM 관련 reference 자료. CTF 에서는 embedded Lua interpreter
(게임/스크립트 엔진), Lua bytecode reverse engineering, sandbox escape,
custom Lua VM challenge 등에서 등장.

## Entries

- [lua-5.0-reference.md](lua-5.0-reference.md) — Lua 5.0 공식 reference manual 요약 (언어 문법 + C API + debug interface + 표준 라이브러리). 원본 PDF 는 `sources/lua/refman-5.0.pdf`.
- [lua-5.0-bytecode-crafting.md](lua-5.0-bytecode-crafting.md) — Lua 5.0 bytecode 작성/생성/패치 방법 (luac CLI / `string.dump` / Python hand-craft / .luac binary surgery / bytecode-level sandbox escape).

## Related raw material

- sources (if present): `sources/lua/refman-5.0.pdf` — 원본 71-page PDF (2003-11-25 revision, MIT 라이선스, www.lua.org/ftp/refman-5.0.pdf)
