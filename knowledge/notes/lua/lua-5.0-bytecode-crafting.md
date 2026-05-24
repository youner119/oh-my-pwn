---
title: Lua 5.0 bytecode 작성/생성 방법
tags: [lang, lua, vm, bytecode, reverse, sandbox-escape]
related_sources:
  - sources/lua/refman-5.0.pdf
last_updated: 2026-05-23
---

# Lua 5.0 bytecode 작성하기

CTF 에서 Lua bytecode 를 *직접 만들거나 손으로 고쳐서* host 인터프리터에
먹여야 할 때가 있다. 흔한 시나리오:

1. Host 가 source Lua 는 차단 / bytecode 만 허용 — 손으로 crafting 필요.
2. Host 가 `loadstring` 의 verifier 를 약하게 박음 — opcode 조작으로
   sandbox escape.
3. Bytecode-only challenge — 주어진 .luac 를 patch 하거나, 의도된
   동작과 다른 chunk 를 새로 만들어야 함.
4. Custom Lua VM 의 opcode table 추정 후 실험용 chunk 생성.

본문은 **표준 Lua 5.0 (0x50)** 기준. 5.1 (0x51) / 5.3 (0x53) / 5.4
(0x54) 는 header 와 opcode 가 다르다 — version byte 확인 후 적용.
헤더/opcode 의 raw layout 은 자매 note
[lua-5.0-reference.md](lua-5.0-reference.md) § 5–6 참조 (본 note 와
중복하지 않음).

---

## 통로 1. `luac` CLI (가장 쉬움)

```bash
# Lua 5.0 toolchain 이 있다면
echo 'print("hi")' > /tmp/a.lua
luac5.0 -o /tmp/a.luac /tmp/a.lua          # 컴파일
luac5.0 -l /tmp/a.luac                     # disassemble (list)
```

- `luac -p` = parse only (문법만 검사).
- `luac -s` = strip debug info (`lineinfo` / `locals` / `upvalue` name).
  Reverser 가 readable 한 거 없애고 싶을 때.
- 여러 source 를 한 .luac 로 묶을 수도 있음 — main chunk 가
  여러 sub-chunk 를 차례로 call.

> 시스템에 Lua 5.0 만 있을 일은 드물다. 보통 `luac` = 5.1 또는 5.3.
> 5.0 toolchain 은 `lua.org/ftp/lua-5.0.3.tar.gz` 직접 빌드가 가장
> 확실. challenge container 에 Lua 5.0 인터프리터가 있다면 컴파일도
> 거기서 하는 게 best — 컴파일러 / 실행기 version mismatch 가 가장
> 흔한 함정.

## 통로 2. `string.dump` (in-process round-trip)

Lua chunk 안에서 동적으로 bytecode 를 얻고 다시 로드한다.

```lua
local f = function() return 1 + 2 end
local bc = string.dump(f)                  -- "\x1bLua\x50..." byte string
local g = loadstring(bc)                   -- 다시 함수로
print(g())                                 -- 3
```

CTF 활용:
- **Verifier 우회**: `string.dump` → 메모리에서 *raw string 으로 한
  바이트씩 edit* → `loadstring`. 5.0/5.1 의 `loadstring` 은 bytecode
  를 거의 그대로 신뢰 → 잘못된 opcode/index 로 OOB read/write 가능.
- **String 으로 보존**: print 해서 hex 로 추출 → 외부에서 분석.

```lua
-- bytecode 를 hex 로 dump
local bc = string.dump(function() return 42 end)
for i = 1, #bc do io.write(string.format("%02x ", string.byte(bc, i))) end
print()
```

`string.dump` 는 *upvalue 미보존* — closure 면 함수 본문만 직렬화되고
captured 값은 빠진다. 5.0/5.1 모두 마찬가지.

## 통로 3. Python 으로 hand-craft (.luac 직접 생성)

Lua interpreter 없이 바이트 단위 조립. 가장 자유롭지만 가장 깨지기
쉽다 — 한 byte 어긋나면 `bad header` / `bad code` 로 거부.

```python
import struct

# 5.0 header
hdr = b"\x1bLua"        # signature
hdr += b"\x50"          # version 5.0
hdr += b"\x00"          # format (official)
hdr += b"\x01"          # endianness: 1 = little
hdr += b"\x04"          # sizeof(int)
hdr += b"\x08"          # sizeof(size_t)        (64-bit host)
hdr += b"\x04"          # sizeof(Instruction)
hdr += b"\x08"          # sizeof(lua_Number)
hdr += b"\x00"          # lua_Number is integral? 0 = double

# helpers
def u32(x):  return struct.pack("<I", x)
def usize(x): return struct.pack("<Q", x)   # size_t on 64-bit LE
def lstring(s):
    if s is None: return usize(0)
    b = s.encode() + b"\x00"                # Lua 5.0 strings: length + bytes + NUL
    return usize(len(b)) + b

def lnumber(x): return struct.pack("<d", x)

# instruction packing (iABC / iABx / iAsBx)
#   bits:  opcode(6) | A(8) | C(9) | B(9)      ← Lua 5.0 의 layout
#   주의: 5.0 의 B/C 순서가 5.1+ 와 다르다. C 가 먼저 (low bits).
def iABC(op, A, B, C):
    return (op & 0x3F) | ((A & 0xFF) << 6) | ((C & 0x1FF) << 14) | ((B & 0x1FF) << 23)
def iABx(op, A, Bx):
    return (op & 0x3F) | ((A & 0xFF) << 6) | ((Bx & 0x3FFFF) << 14)
def iAsBx(op, A, sBx):
    return iABx(op, A, sBx + 131071)        # bias = 2^17 - 1

# Lua 5.0 opcode numbers (refman 부록 / lopcodes.h 참조)
OP_MOVE      = 0
OP_LOADK     = 1
OP_LOADBOOL  = 2
OP_LOADNIL   = 3
OP_GETUPVAL  = 4
OP_GETGLOBAL = 5
OP_GETTABLE  = 6
OP_SETGLOBAL = 7
OP_SETUPVAL  = 8
OP_SETTABLE  = 9
OP_NEWTABLE  = 10
OP_SELF      = 11
OP_ADD       = 12
OP_SUB       = 13
OP_MUL       = 14
OP_DIV       = 15
OP_POW       = 16
OP_UNM       = 17
OP_NOT       = 18
OP_CONCAT    = 19
OP_JMP       = 20
OP_EQ        = 21
OP_LT        = 22
OP_LE        = 23
OP_TEST      = 24
OP_CALL      = 25
OP_TAILCALL  = 26
OP_RETURN    = 27
OP_FORLOOP   = 28
OP_TFORLOOP  = 29
OP_TFORPREP  = 30
OP_SETLIST   = 31
OP_SETLISTO  = 32
OP_CLOSE     = 33
OP_CLOSURE   = 34

# main function prototype — print("hi") 와 동등
src       = lstring("@craft")              # source name
linedef   = u32(0)                          # line defined
nups      = b"\x00"                         # number of upvalues
nparams   = b"\x00"                         # number of params
isvararg  = b"\x00"                         # is_vararg flag
maxstack  = b"\x02"                         # maxstacksize

# 코드 4 instructions:
#   GETGLOBAL  R0, K0    ; R0 = _G["print"]
#   LOADK      R1, K1    ; R1 = "hi"
#   CALL       R0, 2, 1  ; R0(R1)            B=2 (1 arg+1), C=1 (0 returns)
#   RETURN     R0, 1, 0  ; return            B=1 (no returns), C=0
code_ins = [
    iABx(OP_GETGLOBAL, 0, 0),
    iABx(OP_LOADK,     1, 1),
    iABC(OP_CALL,      0, 2, 1),
    iABC(OP_RETURN,    0, 1, 0),
]
code = u32(len(code_ins)) + b"".join(u32(i) for i in code_ins)

# 상수 풀
const_count = 2
consts  = u32(const_count)
consts += b"\x04" + lstring("print")        # type 4 = string
consts += b"\x04" + lstring("hi")
# (type tags: 0=nil, 1=bool+1byte, 3=number+lnumber, 4=string+lstring)

protos  = u32(0)                            # nested prototypes 없음
lineinfo = u32(0)                           # line info 없음 (strip)
locals_ = u32(0)
upvals  = u32(0)

proto = src + linedef + nups + nparams + isvararg + maxstack \
      + code + consts + protos + lineinfo + locals_ + upvals

open("/tmp/craft.luac", "wb").write(hdr + proto)
```

실행:
```bash
lua5.0 /tmp/craft.luac        # → hi
luac5.0 -l /tmp/craft.luac    # disassemble 으로 검증
```

함정:
- **사이즈 필드는 host 환경에 맞춰야 한다.** size_t 가 8 (LP64) vs 4
  (ILP32) — host 가 32-bit 면 `usize` 를 `<I` 로 바꿔야 한다.
- **Endian flag 와 실제 pack endian 일치 필수.** 위는 LE 가정.
- **상수 type tag** — 1 (bool) 은 뒤에 1 byte (0/1), 3 (number) 는
  8 byte double, 4 (string) 는 `lstring`.
- **opcode field layout 의 B/C 위치** — 5.0 은 `[op|A|C|B]` (low →
  high), 5.1 부터 `[op|A|B|C]` 로 바뀐다. 한 칸 swap 만으로 깨진다.
- **`CALL` 의 B 의미**: B=0 = top 까지 모든 인자, B=k = k-1 개 인자.
  C 도 마찬가지 — C=0 = top 까지 모든 return, C=k = k-1 개 return.
- **`RETURN` 의 B**: B=0 = top 까지 모든 값, B=1 = 0 개 return,
  B=k = k-1 개 return.

## 통로 4. 기존 .luac patch (binary surgery)

가장 흔한 CTF 패턴 — luac 한 chunk 의 opcode 한두 개만 바꿔서 다른
동작을 유도.

```bash
xxd challenge.luac > /tmp/a.hex            # disassemble 해서 instruction
                                            # 영역의 offset 확인 (lineinfo /
                                            # constants 도 sliding)
luac5.0 -l challenge.luac                  # PC 별 opcode 와 byte offset
                                            # mental mapping
# 원하는 PC 의 4-byte instruction 만 새 값으로 덮어쓰기
python3 -c "
import struct
b = bytearray(open('challenge.luac','rb').read())
ofs = 0x...  # listing 으로 계산
# 예: NOP 효과 — MOVE R0, R0
b[ofs:ofs+4] = struct.pack('<I', 0)  # OP_MOVE A=0 B=0 C=0
open('patched.luac','wb').write(b)
"
```

함정:
- **header 의 sizeof 필드 건드리면 전체 offset 재계산.** 가급적
  instruction 영역만 만지고 sizeof 는 그대로.
- **debug info (lineinfo) 가 instruction 수와 같은 길이.** instruction
  *개수* 를 바꾸면 lineinfo / locals 영역도 같이 갱신해야 거부 안 됨.
  *값* 만 바꾸는 patch 는 안전.

## 통로 5. lupa / lua-pyhon 으로 host 안에서 만들기

CTF 환경에 Lua interpreter 가 있고 `string.dump` 만 가능하면 통로 2
가 가장 안전. 호스트 코드를 못 건드릴 때 사용:

```python
import lupa
lua = lupa.LuaRuntime()
bc = lua.eval("string.dump(function() return 1+2 end)")  # Python bytes
open("/tmp/x.luac","wb").write(bytes(bc))
```

5.0 까지 정확히 호환되는 lupa build 는 흔치 않다 — challenge container
안에서 직접 `lua -e 'io.stdout:write(string.dump(...))' > x.luac` 이
보통 더 깔끔.

---

## 자주 보는 sandbox escape primitive (bytecode 단)

1. **잘못된 register index 의 GETTABLE/SETTABLE** — verifier 가 약하면
   R[A] 가 stack frame 밖을 가리켜 host C struct 의 인접 메모리
   read/write. Lua 5.0/5.1 의 verifier 는 매우 약하다.
2. **GETUPVAL/SETUPVAL 의 B 가 nups 초과** — closure 의 upvalue 영역
   밖 (사실은 다른 C 구조체) 접근.
3. **LOADK 의 Bx 가 상수 풀 크기 초과** — host 가 상수 fetch 시
   OOB read. type confusion 까지 끌고 갈 수 있음.
4. **CLOSURE 다음의 MOVE/GETUPVAL pseudo-instruction list 가 nups 와
   불일치** — 5.0 의 CLOSURE 는 nups 개의 pseudo-instruction 을 따른다.
   개수 위조 시 PC 가 코드 영역 밖으로 진입.

이런 manual edit 후엔 `luac -l` 로 *읽히기는 하는지* 만 확인하고
바로 host 에 먹여보는 게 빠르다 — 깨졌으면 host 가 즉시 거부 (segv
or "bad code").

## Cross-reference

- 자매 note: [lua-5.0-reference.md](lua-5.0-reference.md) — header
  byte layout (§ 5), opcode set + instruction format (§ 6),
  sandbox escape primitive 의 상위 카탈로그 (§ 7).
- 원본 raw: `sources/lua/refman-5.0.pdf` — 정확한 opcode semantics 는
  refman 의 § 5.0 reference (별도 implementor's manual 도 있음:
  `doc/sblua.pdf` — 본 repo 에는 미포함).
