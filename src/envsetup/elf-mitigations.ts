/**
 * In-house ELF mitigations parser. Reads NX / PIE / Canary / RELRO from a
 * binary file without shelling out to `checksec`.
 *
 * Why in-house? See the T04 pre-work decision in `current-task.md`:
 * `checksec` is a 200-line shell script with output that varies by version
 * and platform. A small TypeScript port of just the four checks we need is
 * deterministic, dependency-free, and easier to test.
 *
 * Scope (M1):
 *   - **NX**: PT_GNU_STACK present and `p_flags & PF_X == 0`. Absent
 *     PT_GNU_STACK → NX off (matches kernel default).
 *   - **PIE**: `e_type == ET_DYN` AND a PT_INTERP segment exists. ET_DYN
 *     alone is true for any shared library; the PT_INTERP test
 *     disambiguates a position-independent executable from a `.so`.
 *   - **Canary**: `__stack_chk_fail` symbol present in either the dynamic
 *     symbol table (`.dynsym`) or the static symbol table (`.symtab`).
 *   - **RELRO**: PT_GNU_RELRO + DT_BIND_NOW (or DF_BIND_NOW / DF_1_NOW) →
 *     "full". PT_GNU_RELRO without bind-now → "partial". Neither → "none".
 *
 * Out of scope for M1: FORTIFY_SOURCE (`*_chk` symbol scan), CET / IBT,
 * shadow stacks. Those land later if a benchmark needs them.
 *
 * The parser supports both ELF32 and ELF64, little- and big-endian, so
 * `i386` and `x86_64` CTF binaries are both covered.
 */

import { readFileSync } from "node:fs"

/**
 * Thrown by {@link parseElfMitigations} on a malformed ELF. The caller in
 * `run-envsetup.ts` catches this and wraps it into an
 * {@link import("./envsetup-error").EnvSetupError} with the right
 * `challengeDir` context. Kept as a separate small class so the parser
 * stays free of OmP-specific context (the "library now, agent later"
 * principle: a future caller might use this parser without an OmP state
 * directory in scope).
 */
export class ElfParseError extends Error {
  readonly binaryPath: string
  readonly reason: string

  constructor(binaryPath: string, reason: string) {
    super(`ELF parse error in ${binaryPath}: ${reason}`)
    this.name = "ElfParseError"
    this.binaryPath = binaryPath
    this.reason = reason
  }
}

/* ── ELF constants ──────────────────────────────────────────────────────── */

const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46])

const EI_CLASS = 4
const EI_DATA = 5

const ELFCLASS32 = 1
const ELFCLASS64 = 2

const ELFDATA2LSB = 1
const ELFDATA2MSB = 2

const ET_DYN = 3

const PT_DYNAMIC = 2
const PT_INTERP = 3
const PT_GNU_STACK = 0x6474e551
const PT_GNU_RELRO = 0x6474e552

const PF_X = 1

const SHT_SYMTAB = 2
const SHT_STRTAB = 3
const SHT_DYNSYM = 11

const DT_NULL = 0
const DT_BIND_NOW = 24
const DT_FLAGS = 30
const DT_FLAGS_1 = 0x6ffffffb

const DF_BIND_NOW = 0x00000008
const DF_1_NOW = 0x00000001

/* ── Public API ─────────────────────────────────────────────────────────── */

export interface ElfMitigations {
  nx: boolean
  pie: boolean
  canary: boolean
  relro: "full" | "partial" | "none"
  /** Compact one-line summary suitable for journal output. */
  raw: string
}

/**
 * Parse the four mitigations supported in M1 from a binary on disk.
 *
 * @throws EnvSetupError({ kind: "elf-parse-error" }) on a malformed ELF.
 */
export function parseElfMitigations(binaryPath: string): ElfMitigations {
  const elf = readElf(binaryPath)

  const nx = computeNx(elf)
  const pie = computePie(elf)
  const canary = computeCanary(elf)
  const relro = computeRelro(elf)

  const raw = `NX=${nx ? "on" : "off"} PIE=${pie ? "on" : "off"} Canary=${canary ? "on" : "off"} RELRO=${relro}`
  return { nx, pie, canary, relro, raw }
}

/**
 * True iff the binary contains a `PT_INTERP` program header. Used by
 * `docker-extract.ts` to distinguish a dynamically linked binary (which
 * needs libc/ld extracted from the image) from a statically linked one
 * (which does not).
 *
 * Returns `false` on any parse error rather than throwing — callers in the
 * extraction path treat "could not determine" the same as "no interp".
 */
export function hasInterpSegment(binaryPath: string): boolean {
  try {
    const elf = readElf(binaryPath)
    return elf.programHeaders.some((ph) => ph.type === PT_INTERP)
  } catch {
    return false
  }
}

/* ── ELF reader ─────────────────────────────────────────────────────────── */

interface ProgramHeader {
  type: number
  flags: number
  offset: number
  filesz: number
}

interface SectionHeader {
  type: number
  link: number
  offset: number
  size: number
  entsize: number
}

interface ParsedElf {
  buffer: Buffer
  is64: boolean
  littleEndian: boolean
  eType: number
  programHeaders: ProgramHeader[]
  sectionHeaders: SectionHeader[]
}

function readElf(binaryPath: string): ParsedElf {
  let buffer: Buffer
  try {
    buffer = readFileSync(binaryPath)
  } catch (cause) {
    throw new ElfParseError(
      binaryPath,
      `failed to read binary: ${(cause as Error).message}`,
    )
  }

  if (buffer.length < 16 || !buffer.subarray(0, 4).equals(ELF_MAGIC)) {
    throw new ElfParseError(binaryPath, "not an ELF file (magic mismatch)")
  }

  const eiClass = buffer[EI_CLASS]
  const eiData = buffer[EI_DATA]
  if (eiClass !== ELFCLASS32 && eiClass !== ELFCLASS64) {
    throw new ElfParseError(binaryPath, `unsupported ELF class ${eiClass}`)
  }
  if (eiData !== ELFDATA2LSB && eiData !== ELFDATA2MSB) {
    throw new ElfParseError(binaryPath, `unsupported ELF endianness ${eiData}`)
  }

  const is64 = eiClass === ELFCLASS64
  const littleEndian = eiData === ELFDATA2LSB

  const minHeaderSize = is64 ? 64 : 52
  if (buffer.length < minHeaderSize) {
    throw new ElfParseError(
      binaryPath,
      `truncated ELF header (${buffer.length} bytes)`,
    )
  }

  const reader = createReader(buffer, littleEndian)
  // ELF header offsets after e_ident:
  //   ELF64: e_type@16, e_phoff@32, e_shoff@40, e_phentsize@54, e_phnum@56,
  //          e_shentsize@58, e_shnum@60
  //   ELF32: e_type@16, e_phoff@28, e_shoff@32, e_phentsize@42, e_phnum@44,
  //          e_shentsize@46, e_shnum@48
  const eType = reader.u16(16)
  const ePhoff = is64 ? Number(reader.u64(32)) : reader.u32(28)
  const eShoff = is64 ? Number(reader.u64(40)) : reader.u32(32)
  const ePhentsize = is64 ? reader.u16(54) : reader.u16(42)
  const ePhnum = is64 ? reader.u16(56) : reader.u16(44)
  const eShentsize = is64 ? reader.u16(58) : reader.u16(46)
  const eShnum = is64 ? reader.u16(60) : reader.u16(48)

  const programHeaders = readProgramHeaders(
    reader,
    is64,
    binaryPath,
    ePhoff,
    ePhentsize,
    ePhnum,
    buffer.length,
  )
  const sectionHeaders = readSectionHeaders(
    reader,
    is64,
    binaryPath,
    eShoff,
    eShentsize,
    eShnum,
    buffer.length,
  )

  return {
    buffer,
    is64,
    littleEndian,
    eType,
    programHeaders,
    sectionHeaders,
  }
}

interface Reader {
  u16(offset: number): number
  u32(offset: number): number
  u64(offset: number): bigint
}

function createReader(buffer: Buffer, littleEndian: boolean): Reader {
  if (littleEndian) {
    return {
      u16: (o) => buffer.readUInt16LE(o),
      u32: (o) => buffer.readUInt32LE(o),
      u64: (o) => buffer.readBigUInt64LE(o),
    }
  }
  return {
    u16: (o) => buffer.readUInt16BE(o),
    u32: (o) => buffer.readUInt32BE(o),
    u64: (o) => buffer.readBigUInt64BE(o),
  }
}

function readProgramHeaders(
  reader: Reader,
  is64: boolean,
  binaryPath: string,
  phoff: number,
  phentsize: number,
  phnum: number,
  fileLength: number,
): ProgramHeader[] {
  if (phnum === 0) {
    return []
  }
  const minEnt = is64 ? 56 : 32
  if (phentsize < minEnt) {
    throw new ElfParseError(
      binaryPath,
      `program header entry size too small (${phentsize})`,
    )
  }
  const end = phoff + phentsize * phnum
  if (end > fileLength) {
    throw new ElfParseError(
      binaryPath,
      `program headers extend past EOF (${end} > ${fileLength})`,
    )
  }

  const headers: ProgramHeader[] = []
  for (let i = 0; i < phnum; i++) {
    const base = phoff + i * phentsize
    const type = reader.u32(base)
    if (is64) {
      // ELF64: p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, ...
      const flags = reader.u32(base + 4)
      const offset = Number(reader.u64(base + 8))
      const filesz = Number(reader.u64(base + 32))
      headers.push({ type, flags, offset, filesz })
    } else {
      // ELF32: p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
      const offset = reader.u32(base + 4)
      const filesz = reader.u32(base + 16)
      const flags = reader.u32(base + 24)
      headers.push({ type, flags, offset, filesz })
    }
  }
  return headers
}

function readSectionHeaders(
  reader: Reader,
  is64: boolean,
  binaryPath: string,
  shoff: number,
  shentsize: number,
  shnum: number,
  fileLength: number,
): SectionHeader[] {
  if (shnum === 0) {
    return []
  }
  const minEnt = is64 ? 64 : 40
  if (shentsize < minEnt) {
    throw new ElfParseError(
      binaryPath,
      `section header entry size too small (${shentsize})`,
    )
  }
  const end = shoff + shentsize * shnum
  if (end > fileLength) {
    throw new ElfParseError(
      binaryPath,
      `section headers extend past EOF (${end} > ${fileLength})`,
    )
  }

  const headers: SectionHeader[] = []
  for (let i = 0; i < shnum; i++) {
    const base = shoff + i * shentsize
    if (is64) {
      // ELF64: sh_name(4), sh_type(4), sh_flags(8), sh_addr(8),
      //        sh_offset(8), sh_size(8), sh_link(4), sh_info(4),
      //        sh_addralign(8), sh_entsize(8)
      const type = reader.u32(base + 4)
      const offset = Number(reader.u64(base + 24))
      const size = Number(reader.u64(base + 32))
      const link = reader.u32(base + 40)
      const entsize = Number(reader.u64(base + 56))
      headers.push({ type, link, offset, size, entsize })
    } else {
      // ELF32: sh_name(4), sh_type(4), sh_flags(4), sh_addr(4),
      //        sh_offset(4), sh_size(4), sh_link(4), sh_info(4),
      //        sh_addralign(4), sh_entsize(4)
      const type = reader.u32(base + 4)
      const offset = reader.u32(base + 16)
      const size = reader.u32(base + 20)
      const link = reader.u32(base + 24)
      const entsize = reader.u32(base + 36)
      headers.push({ type, link, offset, size, entsize })
    }
  }
  return headers
}

/* ── Mitigation computation ─────────────────────────────────────────────── */

function computeNx(elf: ParsedElf): boolean {
  const stack = elf.programHeaders.find((ph) => ph.type === PT_GNU_STACK)
  if (stack === undefined) {
    // No PT_GNU_STACK → kernel default is executable stack (NX off).
    return false
  }
  return (stack.flags & PF_X) === 0
}

function computePie(elf: ParsedElf): boolean {
  if (elf.eType !== ET_DYN) {
    return false
  }
  // ET_DYN binaries can also be plain shared libraries; only those with a
  // PT_INTERP entry are runnable executables (i.e. PIE).
  return elf.programHeaders.some((ph) => ph.type === PT_INTERP)
}

function computeCanary(elf: ParsedElf): boolean {
  const dynsym = elf.sectionHeaders.find((sh) => sh.type === SHT_DYNSYM)
  if (dynsym !== undefined && symbolTableHasName(elf, dynsym, "__stack_chk_fail")) {
    return true
  }
  const symtab = elf.sectionHeaders.find((sh) => sh.type === SHT_SYMTAB)
  if (symtab !== undefined && symbolTableHasName(elf, symtab, "__stack_chk_fail")) {
    return true
  }
  return false
}

function symbolTableHasName(
  elf: ParsedElf,
  symbolSection: SectionHeader,
  needle: string,
): boolean {
  if (symbolSection.entsize === 0) {
    return false
  }
  const stringSection = elf.sectionHeaders[symbolSection.link]
  if (
    stringSection === undefined ||
    stringSection.type !== SHT_STRTAB ||
    stringSection.size === 0
  ) {
    return false
  }
  const strBytes = elf.buffer.subarray(
    stringSection.offset,
    stringSection.offset + stringSection.size,
  )
  const reader = createReader(elf.buffer, elf.littleEndian)
  const count = Math.floor(symbolSection.size / symbolSection.entsize)
  for (let i = 0; i < count; i++) {
    const entryBase = symbolSection.offset + i * symbolSection.entsize
    // st_name is the first u32 in both ELF32 and ELF64 symbol entries.
    const stName = reader.u32(entryBase)
    const name = readCString(strBytes, stName)
    if (name === needle) {
      return true
    }
  }
  return false
}

function readCString(buffer: Buffer, offset: number): string {
  if (offset >= buffer.length) {
    return ""
  }
  const end = buffer.indexOf(0, offset)
  const stop = end === -1 ? buffer.length : end
  return buffer.subarray(offset, stop).toString("utf-8")
}

function computeRelro(elf: ParsedElf): "full" | "partial" | "none" {
  const hasGnuRelro = elf.programHeaders.some((ph) => ph.type === PT_GNU_RELRO)
  if (!hasGnuRelro) {
    return "none"
  }
  if (hasBindNow(elf)) {
    return "full"
  }
  return "partial"
}

function hasBindNow(elf: ParsedElf): boolean {
  const dynamicHeader = elf.programHeaders.find((ph) => ph.type === PT_DYNAMIC)
  if (dynamicHeader === undefined) {
    return false
  }
  const reader = createReader(elf.buffer, elf.littleEndian)
  const entrySize = elf.is64 ? 16 : 8
  const start = dynamicHeader.offset
  const end = Math.min(start + dynamicHeader.filesz, elf.buffer.length)
  for (let cursor = start; cursor + entrySize <= end; cursor += entrySize) {
    const tag = elf.is64 ? Number(reader.u64(cursor)) : reader.u32(cursor)
    const val = elf.is64
      ? Number(reader.u64(cursor + 8))
      : reader.u32(cursor + 4)
    if (tag === DT_NULL) {
      break
    }
    if (tag === DT_BIND_NOW) {
      return true
    }
    if (tag === DT_FLAGS && (val & DF_BIND_NOW) !== 0) {
      return true
    }
    if (tag === DT_FLAGS_1 && (val & DF_1_NOW) !== 0) {
      return true
    }
  }
  return false
}

