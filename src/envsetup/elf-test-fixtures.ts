/**
 * In-memory ELF byte-buffer builder used by `elf-mitigations.test.ts` and
 * (in the future) any other test that needs to assert behaviour on a
 * synthetic ELF file. NOT exported from `index.ts`; tests only.
 *
 * Why hand-crafted: real ELF binaries vary across compilers/glibc versions
 * and we want each test case to pin _exactly_ the structural detail it
 * cares about (e.g. "PT_GNU_STACK with PF_X=0 → NX on") without dragging
 * in 80KB of unrelated bytes. The builder produces minimum-viable
 * little-endian ELF buffers that satisfy the parser in
 * `elf-mitigations.ts`.
 *
 * Scope: ELF64 + ELF32, little-endian only. Big-endian is supported by
 * the parser but exotic for CTF binaries; we test endianness branching
 * via a focused parse-only test, not the full builder.
 *
 * @internal
 */

const ELFCLASS32 = 1
const ELFCLASS64 = 2
const ELFDATA2LSB = 1

const ET_EXEC = 2
const ET_DYN = 3

const PT_DYNAMIC = 2

const SHT_PROGBITS = 1
const SHT_SYMTAB = 2
const SHT_STRTAB = 3
const SHT_DYNSYM = 11
const SHT_DYNAMIC = 6

export interface SyntheticDynamicEntry {
  tag: number
  val: number
}

export interface SyntheticProgramHeader {
  type: number
  flags?: number
  /** Set to true for the PT_DYNAMIC entry — the builder wires its offset/filesz to the dynamic table. */
  pointsAtDynamic?: boolean
}

export interface SyntheticElfOptions {
  class?: 32 | 64
  type?: "exec" | "dyn"
  programHeaders?: SyntheticProgramHeader[]
  dynamic?: SyntheticDynamicEntry[]
  /** Symbol names to put in .dynsym. The first entry is always the null symbol; do not include it. */
  dynsymNames?: string[]
  /** Symbol names to put in .symtab. */
  symtabNames?: string[]
}

interface Layout {
  is64: boolean
  ehsize: number
  phentsize: number
  shentsize: number
  symentsize: number
  dynentsize: number
}

function layoutFor(is64: boolean): Layout {
  return {
    is64,
    ehsize: is64 ? 64 : 52,
    phentsize: is64 ? 56 : 32,
    shentsize: is64 ? 64 : 40,
    symentsize: is64 ? 24 : 16,
    dynentsize: is64 ? 16 : 8,
  }
}

interface SectionPlan {
  type: number
  link: number
  data: Buffer
  offset: number
  entsize: number
}

/** Build a synthetic little-endian ELF buffer matching `opts`. */
export function buildElfFixture(opts: SyntheticElfOptions = {}): Buffer {
  const is64 = (opts.class ?? 64) === 64
  const layout = layoutFor(is64)

  // Section data — assemble first so we know each section's size before
  // we lay them out in the file.
  const sections: SectionPlan[] = []

  // Section 0 is always the SHN_UNDEF reserved entry.
  sections.push({ type: 0, link: 0, data: Buffer.alloc(0), offset: 0, entsize: 0 })

  // Optional .dynsym + .dynstr pair.
  if (opts.dynsymNames !== undefined && opts.dynsymNames.length > 0) {
    const { strtabBuffer, nameOffsets } = buildStringTable(opts.dynsymNames)
    const dynstrIndex = sections.length
    sections.push({
      type: SHT_STRTAB,
      link: 0,
      data: strtabBuffer,
      offset: 0,
      entsize: 0,
    })
    const dynsymBuffer = buildSymbolTable(layout, nameOffsets)
    sections.push({
      type: SHT_DYNSYM,
      link: dynstrIndex,
      data: dynsymBuffer,
      offset: 0,
      entsize: layout.symentsize,
    })
  }

  // Optional .symtab + .strtab pair (mirrors .dynsym/.dynstr).
  if (opts.symtabNames !== undefined && opts.symtabNames.length > 0) {
    const { strtabBuffer, nameOffsets } = buildStringTable(opts.symtabNames)
    const strtabIndex = sections.length
    sections.push({
      type: SHT_STRTAB,
      link: 0,
      data: strtabBuffer,
      offset: 0,
      entsize: 0,
    })
    const symtabBuffer = buildSymbolTable(layout, nameOffsets)
    sections.push({
      type: SHT_SYMTAB,
      link: strtabIndex,
      data: symtabBuffer,
      offset: 0,
      entsize: layout.symentsize,
    })
  }

  // Optional .dynamic — both as a section (so SHT_DYNAMIC is present) AND
  // as data that PT_DYNAMIC's offset/filesz will point at.
  let dynamicData: Buffer = Buffer.alloc(0)
  if (opts.dynamic !== undefined && opts.dynamic.length > 0) {
    dynamicData = buildDynamicTable(layout, opts.dynamic)
    sections.push({
      type: SHT_DYNAMIC,
      link: 0,
      data: dynamicData,
      offset: 0,
      entsize: layout.dynentsize,
    })
  }

  // Compute file layout: ELF header → program headers → section data → section headers.
  const phnum = (opts.programHeaders ?? []).length
  const shnum = sections.length
  let cursor = layout.ehsize + layout.phentsize * phnum

  // Reserve a tiny .shstrtab so the section header table has a string table to point at.
  // The parser does not actually read .shstrtab so an empty stub is fine.
  const shstrtabIndex = sections.length
  sections.push({
    type: SHT_STRTAB,
    link: 0,
    data: Buffer.from([0]),
    offset: 0,
    entsize: 0,
  })

  // Place each non-null section's data sequentially.
  for (const section of sections) {
    if (section.data.length === 0) {
      continue
    }
    section.offset = cursor
    cursor += section.data.length
  }
  const shoff = cursor
  cursor += layout.shentsize * sections.length
  const totalSize = cursor

  const buf = Buffer.alloc(totalSize)

  // ELF identification.
  buf[0] = 0x7f
  buf[1] = 0x45 // 'E'
  buf[2] = 0x4c // 'L'
  buf[3] = 0x46 // 'F'
  buf[4] = is64 ? ELFCLASS64 : ELFCLASS32
  buf[5] = ELFDATA2LSB
  buf[6] = 1 // EV_CURRENT

  // ELF header fields.
  const eType = (opts.type ?? "exec") === "dyn" ? ET_DYN : ET_EXEC
  buf.writeUInt16LE(eType, 16) // e_type
  buf.writeUInt16LE(62, 18) // e_machine = EM_X86_64 (arbitrary, parser ignores)
  buf.writeUInt32LE(1, 20) // e_version

  if (is64) {
    buf.writeBigUInt64LE(0n, 24) // e_entry
    buf.writeBigUInt64LE(BigInt(layout.ehsize), 32) // e_phoff
    buf.writeBigUInt64LE(BigInt(shoff), 40) // e_shoff
    buf.writeUInt32LE(0, 48) // e_flags
    buf.writeUInt16LE(layout.ehsize, 52)
    buf.writeUInt16LE(layout.phentsize, 54)
    buf.writeUInt16LE(phnum, 56)
    buf.writeUInt16LE(layout.shentsize, 58)
    buf.writeUInt16LE(shnum, 60)
    buf.writeUInt16LE(shstrtabIndex, 62)
  } else {
    buf.writeUInt32LE(0, 24) // e_entry
    buf.writeUInt32LE(layout.ehsize, 28) // e_phoff
    buf.writeUInt32LE(shoff, 32) // e_shoff
    buf.writeUInt32LE(0, 36) // e_flags
    buf.writeUInt16LE(layout.ehsize, 40)
    buf.writeUInt16LE(layout.phentsize, 42)
    buf.writeUInt16LE(phnum, 44)
    buf.writeUInt16LE(layout.shentsize, 46)
    buf.writeUInt16LE(shnum, 48)
    buf.writeUInt16LE(shstrtabIndex, 50)
  }

  // Program headers.
  let phCursor = layout.ehsize
  for (const ph of opts.programHeaders ?? []) {
    const offset = ph.pointsAtDynamic === true ? findDynamicOffset(sections) : 0
    const filesz =
      ph.pointsAtDynamic === true ? dynamicData.length : 0
    if (is64) {
      buf.writeUInt32LE(ph.type, phCursor)
      buf.writeUInt32LE(ph.flags ?? 0, phCursor + 4)
      buf.writeBigUInt64LE(BigInt(offset), phCursor + 8)
      buf.writeBigUInt64LE(0n, phCursor + 16) // p_vaddr
      buf.writeBigUInt64LE(0n, phCursor + 24) // p_paddr
      buf.writeBigUInt64LE(BigInt(filesz), phCursor + 32)
      buf.writeBigUInt64LE(BigInt(filesz), phCursor + 40) // p_memsz
      buf.writeBigUInt64LE(0n, phCursor + 48) // p_align
    } else {
      buf.writeUInt32LE(ph.type, phCursor)
      buf.writeUInt32LE(offset, phCursor + 4)
      buf.writeUInt32LE(0, phCursor + 8) // p_vaddr
      buf.writeUInt32LE(0, phCursor + 12) // p_paddr
      buf.writeUInt32LE(filesz, phCursor + 16)
      buf.writeUInt32LE(filesz, phCursor + 20) // p_memsz
      buf.writeUInt32LE(ph.flags ?? 0, phCursor + 24)
      buf.writeUInt32LE(0, phCursor + 28) // p_align
    }
    phCursor += layout.phentsize
  }

  // Section data.
  for (const section of sections) {
    if (section.data.length === 0) {
      continue
    }
    section.data.copy(buf, section.offset)
  }

  // Section headers.
  let shCursor = shoff
  for (const section of sections) {
    if (is64) {
      buf.writeUInt32LE(0, shCursor) // sh_name
      buf.writeUInt32LE(section.type, shCursor + 4)
      buf.writeBigUInt64LE(0n, shCursor + 8) // sh_flags
      buf.writeBigUInt64LE(0n, shCursor + 16) // sh_addr
      buf.writeBigUInt64LE(BigInt(section.offset), shCursor + 24)
      buf.writeBigUInt64LE(BigInt(section.data.length), shCursor + 32)
      buf.writeUInt32LE(section.link, shCursor + 40)
      buf.writeUInt32LE(0, shCursor + 44) // sh_info
      buf.writeBigUInt64LE(0n, shCursor + 48) // sh_addralign
      buf.writeBigUInt64LE(BigInt(section.entsize), shCursor + 56)
    } else {
      buf.writeUInt32LE(0, shCursor) // sh_name
      buf.writeUInt32LE(section.type, shCursor + 4)
      buf.writeUInt32LE(0, shCursor + 8) // sh_flags
      buf.writeUInt32LE(0, shCursor + 12) // sh_addr
      buf.writeUInt32LE(section.offset, shCursor + 16)
      buf.writeUInt32LE(section.data.length, shCursor + 20)
      buf.writeUInt32LE(section.link, shCursor + 24)
      buf.writeUInt32LE(0, shCursor + 28) // sh_info
      buf.writeUInt32LE(0, shCursor + 32) // sh_addralign
      buf.writeUInt32LE(section.entsize, shCursor + 36)
    }
    shCursor += layout.shentsize
  }

  return buf
}

function buildStringTable(names: string[]): {
  strtabBuffer: Buffer
  nameOffsets: number[]
} {
  // Strtab always begins with a null byte so st_name=0 → empty string.
  const parts: Buffer[] = [Buffer.from([0])]
  const offsets: number[] = []
  let cursor = 1
  for (const name of names) {
    offsets.push(cursor)
    const bytes = Buffer.from(`${name}\0`, "utf-8")
    parts.push(bytes)
    cursor += bytes.length
  }
  return {
    strtabBuffer: Buffer.concat(parts),
    nameOffsets: offsets,
  }
}

function buildSymbolTable(layout: Layout, nameOffsets: number[]): Buffer {
  // First entry is the null symbol (all zeros).
  const count = nameOffsets.length + 1
  const buf = Buffer.alloc(count * layout.symentsize)
  for (let i = 0; i < nameOffsets.length; i++) {
    const base = (i + 1) * layout.symentsize
    buf.writeUInt32LE(nameOffsets[i]!, base)
    // st_info, st_other, st_shndx, st_value, st_size — all zero is fine.
  }
  return buf
}

function buildDynamicTable(
  layout: Layout,
  entries: SyntheticDynamicEntry[],
): Buffer {
  // Append a DT_NULL terminator to mirror real binaries.
  const all: SyntheticDynamicEntry[] = [...entries, { tag: 0, val: 0 }]
  const buf = Buffer.alloc(all.length * layout.dynentsize)
  let cursor = 0
  for (const entry of all) {
    if (layout.is64) {
      buf.writeBigInt64LE(BigInt(entry.tag), cursor)
      buf.writeBigUInt64LE(BigInt(entry.val), cursor + 8)
    } else {
      buf.writeInt32LE(entry.tag, cursor)
      buf.writeUInt32LE(entry.val, cursor + 4)
    }
    cursor += layout.dynentsize
  }
  return buf
}

function findDynamicOffset(sections: SectionPlan[]): number {
  const dynamic = sections.find((s) => s.type === SHT_DYNAMIC)
  return dynamic?.offset ?? 0
}

/* Re-exported constants for test convenience. */
export const TEST_PT_LOAD = 1
export const TEST_PT_DYNAMIC = PT_DYNAMIC
export const TEST_PT_INTERP = 3
export const TEST_PT_GNU_STACK = 0x6474e551
export const TEST_PT_GNU_RELRO = 0x6474e552
export const TEST_PF_X = 1
export const TEST_PF_W = 2
export const TEST_PF_R = 4
export const TEST_DT_BIND_NOW = 24
export const TEST_DT_FLAGS = 30
export const TEST_DT_FLAGS_1 = 0x6ffffffb
export const TEST_DF_BIND_NOW = 0x00000008
export const TEST_DF_1_NOW = 0x00000001
export const TEST_SHT_PROGBITS = SHT_PROGBITS
