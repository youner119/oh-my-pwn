---
title: Lua 5.0 Reference Manual (요약)
tags: [lang, lua, vm, embedded-scripting, reverse]
related_sources:
  - sources/lua/refman-5.0.pdf
last_updated: 2026-05-23
---

# Lua 5.0 Reference Manual

Lua 5.0 공식 reference manual (Roberto Ierusalimschy, Luiz Henrique de
Figueiredo, Waldemar Celes — PUC-Rio, 2003-11-25, MIT). 71 페이지.
원본 PDF: `sources/lua/refman-5.0.pdf` (부재 시 silently skip).
www.lua.org/ftp/refman-5.0.pdf 에서 재취득 가능.

> Lua 5.0 은 **register-based VM** 으로 전환된 첫 버전 (이전 4.0 까지는
> stack-based). CTF 에서 만나는 embedded Lua / 5.1 LuaJIT / 5.3+ 와
> 표면적으로 비슷하지만 bytecode layout / opcode set / global 환경
> 모델 / closure 구현이 버전마다 다르다 — version-specific dispatch
> 가 필요하면 항상 binary 의 LUA_SIGNATURE (`\x1bLua`) 뒤 1 byte
> version field 확인.

## 1. 왜 PWN/RE 에서 보는가

- **Embedded interpreter sandbox escape** — 게임/장치 firmware/네트워크
  appliance 가 Lua 를 설정/스크립트 엔진으로 박는다. `loadstring` /
  `dofile` / metatable / `getfenv` / `debug` 라이브러리 노출 여부가
  escape primitive 결정.
- **Lua bytecode RE** — `luac` precompiled chunk 만 배포된 챌린지.
  Header (`\x1bLua\x50<...>`) + function prototype tree 파싱이 첫 단계.
- **Custom Lua VM** — opcode table 만 바꿔서 obfuscation 으로 쓰는
  케이스. 표준 5.0 opcode (`OP_MOVE`, `OP_LOADK`, ... `OP_CLOSE`,
  `OP_CLOSURE`) 와 dispatch 패턴을 알면 swap 만 역해독 시 빠르다.
- **Native C API misuse** — host C 코드가 `lua_*` API 를 잘못 써서
  stack underflow / type confusion / userdata UAF 생기는 경우. C API
  계약을 알아야 어디서 깨지는지 보인다.

## 2. PDF 목차 (간추림)

```
1. Introduction
2. The Language                                p.1
   2.1 Lexical Conventions
   2.2 Values and Types  (nil, boolean, number=double, string,
                          function, userdata, thread, table)
       2.2.1 Coercion (string↔number 자동)
   2.3 Variables (global=환경 table 키, local, upvalue)
   2.4 Statements  (chunks, blocks, assignment, control, for,
                    function call, local)
   2.5 Expressions (arith, relational, logical, concat `..`,
                    precedence, table constructor, call,
                    function definition)
   2.6 Visibility Rules (lexical scoping, upvalue closure)
   2.7 Error Handling (error / pcall)
   2.8 Metatables (__index, __newindex, __add, __eq, __lt,
                   __call, __tostring, __metatable lock)
   2.9 Garbage Collection
       2.9.1 GC Metamethods (__gc on userdata)
       2.9.2 Weak Tables (__mode = "k"/"v"/"kv")
   2.10 Coroutines (resume / yield / status — asymmetric)
3. The Application Program Interface           p.22
   3.1  States (lua_State, lua_open/close, threads share globals)
   3.2  The Stack and Indices (positive/negative/pseudo —
        LUA_GLOBALSINDEX, LUA_REGISTRYINDEX, upvalue indices)
   3.3  Stack Manipulation (gettop/settop/push*/pop/insert/
                            remove/replace)
   3.4  Querying the Stack (type, isnumber, isstring, ...)
   3.5  Getting Values (tonumber/tostring/tolstring/topointer/
                        touserdata)
   3.6  Pushing Values (pushnumber/pushstring/pushcfunction/
                        pushlightuserdata/pushvalue)
   3.7  Controlling GC (lua_getgccount/threshold)
   3.8  Userdata (newuserdata — full vs. light)
   3.9  Metatables (getmetatable/setmetatable)
   3.10 Loading Lua Chunks (lua_load + reader callback)
   3.11 Manipulating Tables (gettable/settable/rawget/rawset —
                             raw 가 metamethod 우회)
   3.12 Manipulating Environments (getfenv/setfenv)
   3.13 Using Tables as Arrays (getn)
   3.14 Calling Functions (lua_call)
   3.15 Protected Calls (lua_pcall — error 시 stack unwind)
   3.16 Defining C Functions (lua_CFunction)
   3.17 Defining C Closures (pushcclosure + upvalueindex)
4. The Debug Interface                         p.35
   4.1 Stack and Function Information (lua_Debug, getstack,
                                       getinfo)
   4.2 Manipulating Local Variables and Upvalues
       (getlocal/setlocal/getupvalue/setupvalue)
   4.3 Hooks (sethook — CALL/RET/LINE/COUNT events)
5. Standard Libraries                          p.38
   5.1 Basic (print, type, tostring/tonumber, error, pcall,
              ipairs/pairs/next, loadstring/loadfile/dofile,
              getfenv/setfenv, getmetatable/setmetatable,
              rawequal/rawget/rawset, collectgarbage,
              require/_REQUIREDNAME, assert, unpack)
   5.2 Coroutine (coroutine.create/resume/yield/status/wrap)
   5.3 String (string.byte/char/dump/find/format/gmatch/gsub/
               len/lower/match/rep/reverse/sub/upper)
       — Lua 5.0 의 string.dump 가 bytecode serialize 시작점.
   5.4 Table (table.concat/insert/remove/sort/getn/setn)
   5.5 Math (math.* — sin/cos/exp/log/floor/ceil/random/...)
   5.6 IO (io.open/close/read/write/lines/stdin/stdout/stderr,
           file:* methods)
   5.7 OS (os.clock/date/difftime/execute/exit/getenv/remove/
           rename/setlocale/time/tmpname)
   5.8 Reflexive Debug (debug.debug/getinfo/getlocal/setlocal/
                        gethook/sethook/getupvalue/setupvalue/
                        traceback) — sandbox escape 단골.
6. Lua Stand-alone (lua / luac 실행 파일)        p.57
```

## 3. 5.0 만의 특징 (5.1+ 대비)

- **`getfenv` / `setfenv` 로 함수의 environment 교체 가능** — 5.1 까지
  유지되다가 5.2 부터 `_ENV` upvalue 로 대체. sandbox escape 의 고전
  primitive (예: hostile 함수의 fenv 를 진짜 `_G` 로 swap).
- **`module` / `require` 가 5.0 도입.** Package system 의 초기 형태.
- **Integer 별도 type 없음.** 모든 number = double. 5.3 부터 integer
  subtype 추가.
- **`goto` / label 없음** (5.2 도입).
- **`bit32` / `bit` 표준 안 박힘** — host C 가 추가로 노출하는 경우만.
- **`#` length operator 는 있지만 metatable `__len` 미적용** (5.1 부터
  table 외에도 적용 확대).
- **`continue` 없음** (모든 버전 공통).

## 4. C API 패턴 (sandbox escape / host bug 관점)

| Primitive | 위험 표면 |
|---|---|
| `lua_pushcclosure` + upvalueindex | upvalue 누설 시 C 클로저 capture 값 leak |
| `lua_newuserdata` + `__gc` metatable | full userdata UAF — host 가 raw pointer 보관하다 GC 후 dangle |
| `lua_rawget` / `rawset` | metatable 우회 — host 가 sanity check 를 metatable 에 박았으면 우회 가능 |
| `lua_pcall` 의 error handler 인덱스 | stack 의 잘못된 인덱스 지정 시 host crash |
| `lua_load` + reader callback | malformed bytecode 가 verifier 우회 → opcode confusion |
| `LUA_GLOBALSINDEX` / `LUA_REGISTRYINDEX` | 모든 sandbox 가 `_G` / registry 차단 못 하면 백도어 |

## 5. Lua bytecode header (5.0 specific)

```
offset  size  field
 0      4     "\x1bLua"  (signature)
 4      1     version = 0x50      ← 5.0
 5      1     format = 0          ← official
 6      1     endianness (1 = LE)
 7      1     sizeof(int)
 8      1     sizeof(size_t)
 9      1     sizeof(Instruction) = 4
10      1     sizeof(lua_Number) = typically 8
11      1     lua_Number is integral (0 = double)
12+     ...   top-level function prototype
```

이후 function prototype 은 재귀적 — `source name` (length-prefixed
string) → `line defined` → `nups` → `numparams` → `is_vararg` →
`maxstacksize` → `code[]` → `constants[]` (typed: nil/bool/num/str) →
`prototypes[]` (nested) → `lineinfo[]` → `locals[]` → `upvalues[]`.

5.1 은 `version = 0x51`, `nups` 위치 다름, debug info layout 변경.
5.0 vs 5.1 mix-up 자주 발생 — 항상 byte 5 확인.

## 6. 5.0 register VM opcode (참고 카탈로그)

5.0 instruction = 32-bit, format 3 종:
- **iABC**: 6-bit opcode + A(8) + B(9) + C(9) — `MOVE`, `ADD`, ...
- **iABx**: 6-bit opcode + A(8) + Bx(18) — `LOADK`, `GETGLOBAL`,
  `SETGLOBAL`, `CLOSURE`, `JMP` (signed)
- **iAsBx**: `JMP`, `FORLOOP`, `FORPREP` (signed Bx)

주요 opcode (5.0 set, 38 개):
```
MOVE LOADK LOADBOOL LOADNIL
GETUPVAL GETGLOBAL GETTABLE
SETGLOBAL SETUPVAL SETTABLE
NEWTABLE SELF
ADD SUB MUL DIV POW UNM NOT CONCAT
JMP EQ LT LE TEST
CALL TAILCALL RETURN
FORLOOP TFORLOOP TFORPREP FORPREP
SETLIST SETLISTO   ← 5.0 만의 분리 (5.1 에서 통합)
CLOSE CLOSURE
```

> 5.0 의 `SETLIST` / `SETLISTO` 분리, `TFORPREP` 존재, `VARARG` opcode
> 부재 (5.1 에서 추가) — buffer 가 어느 5.x 인지 빠르게 판별하는 지문.

## 7. Sandbox escape — 자주 보는 chain

1. **`debug.getregistry` 접근 가능?** → registry 에서 임의 객체 끌어옴.
2. **`debug.getupvalue` / `debug.setupvalue`** → 보호된 closure 의
   captured local 직접 읽기/쓰기. sandbox 가 만든 "안전한" wrapper
   안의 진짜 함수 reference 탈취.
3. **`string.dump` + `loadstring`** → bytecode round-trip 으로
   verifier 우회 (5.0/5.1 의 verifier 가 약하기로 유명).
4. **Metatable 의 `__index` / `__call` 이 native C 함수** → host 가
   blacklist 만 했고 metamethod 노출 안 막은 경우 raw 접근.
5. **`coroutine.create` 안의 `yield` 후 `resume` 으로 stack 상태
   pivot** — 흔치 않지만 본 적은 있음.
6. **`getfenv(0)` / `getfenv(coroutine_func)`** — 5.0/5.1 한정. 진짜
   `_G` 손에 넣음.

## 8. Cross-reference

- Vendor: `ctf-reverse/` — 추후 Lua bytecode 관련 SKILL 추가 시 link.
- Vendor: `ctf-pwn/` — `loadstring` / native C API bug 가 host process
  pwn 으로 이어지는 경우 link.
- Writeups: (없음 — 추가 시 양방향 link).
