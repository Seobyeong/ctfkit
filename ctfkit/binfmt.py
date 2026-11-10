"""ELF / PE 실행 파일 파서. 표준 라이브러리(struct)만 사용한다. 외부 의존성 없음.

`rev` 명령이 쓴다. 바이너리의 아키텍처·섹션·심볼을 뽑고, 가상주소(entry 등)를
파일 오프셋으로 바꿔 주는 것까지가 이 모듈의 역할이다. 디스어셈블(capstone)은
여기서 하지 않고, 여기서 얻은 (arch, 오프셋, 바이트) 를 rev.disasm 이 넘겨받는다.

지원 범위는 CTF 입문에서 흔한 것만: ELF32/64(LE/BE), PE32/PE32+.
"""

import struct
from dataclasses import dataclass, field

from ctfkit.registry import TransformError

# ELF e_machine -> (사람이 읽는 이름, capstone 친화 아키텍처 키)
# 아키텍처 키는 rev.disasm 이 capstone 상수로 매핑할 때 쓴다.
_ELF_MACHINE = {
    0x03: ("x86", "x86"),
    0x3E: ("x86-64", "x64"),
    0x28: ("ARM", "arm"),
    0xB7: ("AArch64", "arm64"),
    0x08: ("MIPS", "mips"),
    0xF3: ("RISC-V", "riscv"),
    0x16: ("s390", None),
    0x14: ("PowerPC", None),
}

# PE machine -> (이름, 아키텍처 키)
_PE_MACHINE = {
    0x014C: ("x86", "x86"),
    0x8664: ("x86-64", "x64"),
    0x01C0: ("ARM", "arm"),
    0xAA64: ("ARM64", "arm64"),
}

_ELF_TYPE = {1: "REL (오브젝트)", 2: "EXEC (실행)", 3: "DYN (PIE/공유)", 4: "CORE"}

_SHT_NOBITS = 8
_SHT_SYMTAB = 2
_SHT_DYNSYM = 11
_STT_FUNC = 2
_STT_OBJECT = 1

# 프로그램 헤더(세그먼트) 타입 — checksec 에서 쓴다
PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 1  # 세그먼트 실행 권한 비트

# .dynamic 태그 — RELRO(full) 판정에 쓴다
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1


@dataclass
class Section:
    name: str
    addr: int        # 가상주소 (sh_addr / PE VirtualAddress 는 RVA)
    offset: int      # 파일 오프셋
    size: int        # 가상 크기 (주소 범위 매칭용)
    filesize: int    # 파일에 실제로 존재하는 바이트 수 (읽기 클램프용; NOBITS 는 0)


@dataclass
class Segment:
    type: int        # PT_LOAD / PT_GNU_STACK ...
    flags: int       # PF_X|PF_W|PF_R
    offset: int      # 파일 오프셋
    vaddr: int       # 가상주소
    filesz: int      # 파일에 있는 크기
    memsz: int       # 메모리에서의 크기


@dataclass
class Symbol:
    name: str
    addr: int
    kind: str        # "FUNC" | "OBJECT"


@dataclass
class BinInfo:
    fmt: str                 # "ELF" | "PE"
    bits: int                # 32 | 64
    endian: str              # "little" | "big"
    machine: str             # 사람이 읽는 이름
    arch: str | None         # capstone 아키텍처 키 (지원 안 하면 None)
    kind: str                # 파일 종류 설명
    entry: int               # 엔트리 포인트 (ELF=가상주소, PE=RVA)
    sections: list[Section] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    segments: list[Segment] = field(default_factory=list)   # ELF 프로그램 헤더
    dynamic: dict[int, int] = field(default_factory=dict)    # ELF .dynamic 태그->값
    extra: dict = field(default_factory=dict)                # 형식별 추가(e_type, PE DllCharacteristics 등)

    def section_at(self, vaddr: int) -> Section | None:
        """주어진 가상주소를 담고 있는, 파일 바이트가 있는 섹션을 찾는다."""
        for s in self.sections:
            if s.filesize and s.addr <= vaddr < s.addr + s.size:
                return s
        return None

    def exec_segments(self) -> list[Segment]:
        """실행 권한이 있고 파일 바이트가 있는 세그먼트 (ROP 가젯 검색용)."""
        return [s for s in self.segments if (s.flags & PF_X) and s.filesz]


def _cstr(data: bytes, start: int) -> str:
    """start 위치에서 널 종료 문자열을 읽는다."""
    end = data.find(b"\x00", start)
    if end < 0:
        end = len(data)
    return data[start:end].decode("utf-8", "replace")


def parse(data: bytes) -> BinInfo:
    """바이너리를 식별해 ELF/PE 를 파싱한다. 알 수 없으면 TransformError."""
    if data[:4] == b"\x7fELF":
        return _parse_elf(data)
    if data[:2] == b"MZ":
        return _parse_pe(data)
    raise TransformError("ELF(\\x7fELF) 도 PE(MZ) 도 아닙니다. 지원하지 않는 형식입니다")


def _unpack(fmt: str, data: bytes, offset: int, what: str):
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        raise TransformError(f"{what} 를 읽다가 파일 끝을 넘었습니다 (손상됐거나 잘린 파일)")
    return struct.unpack_from(fmt, data, offset)


def _parse_elf(data: bytes) -> BinInfo:
    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        raise TransformError(f"알 수 없는 ELF 클래스: {ei_class} (1=32bit, 2=64bit 만 지원)")
    bits = 32 if ei_class == 1 else 64
    en = "<" if ei_data == 1 else ">"
    endian = "little" if ei_data == 1 else "big"

    e_type, e_machine = _unpack(en + "HH", data, 16, "ELF 헤더")
    if bits == 64:
        e_entry, e_phoff, e_shoff = _unpack(en + "QQQ", data, 24, "ELF 헤더")
        e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
            _unpack(en + "HHHHH", data, 54, "ELF 헤더")
    else:
        e_entry, e_phoff, e_shoff = _unpack(en + "III", data, 24, "ELF 헤더")
        e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
            _unpack(en + "HHHHH", data, 42, "ELF 헤더")

    machine, arch = _ELF_MACHINE.get(e_machine, (f"unknown(0x{e_machine:x})", None))
    info = BinInfo(
        fmt="ELF", bits=bits, endian=endian, machine=machine, arch=arch,
        kind=_ELF_TYPE.get(e_type, f"0x{e_type:x}"), entry=e_entry,
    )
    info.extra["e_type"] = e_type

    _parse_elf_segments(data, en, bits, e_phoff, e_phentsize, e_phnum, info)
    _parse_elf_dynamic(data, en, bits, info)

    if e_shoff == 0 or e_shnum == 0:
        return info  # 섹션 헤더가 없는 파일

    # 섹션 헤더들을 먼저 읽고, 섹션 이름 문자열 테이블로 이름을 붙인다
    raw_sections = []
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        if bits == 64:
            sh_name, sh_type = _unpack(en + "II", data, base, "섹션 헤더")
            sh_addr, sh_offset, sh_size = _unpack(en + "QQQ", data, base + 16, "섹션 헤더")
        else:
            sh_name, sh_type = _unpack(en + "II", data, base, "섹션 헤더")
            sh_addr, sh_offset, sh_size = _unpack(en + "III", data, base + 12, "섹션 헤더")
        raw_sections.append((sh_name, sh_type, sh_addr, sh_offset, sh_size, base))

    shstr_off = raw_sections[e_shstrndx][3] if e_shstrndx < len(raw_sections) else 0
    for sh_name, sh_type, sh_addr, sh_offset, sh_size, _base in raw_sections:
        name = _cstr(data, shstr_off + sh_name) if shstr_off else ""
        filesize = 0 if sh_type == _SHT_NOBITS else sh_size
        info.sections.append(Section(name, sh_addr, sh_offset, sh_size, filesize))

    _parse_elf_symbols(data, en, bits, raw_sections, info)
    return info


def _parse_elf_symbols(data, en, bits, raw_sections, info):
    """.symtab(없으면 .dynsym)에서 함수/객체 심볼을 뽑는다."""
    symtab = next((s for s in raw_sections if s[1] == _SHT_SYMTAB), None)
    if symtab is None:
        symtab = next((s for s in raw_sections if s[1] == _SHT_DYNSYM), None)
    if symtab is None:
        return
    # sh_link = 심볼 이름이 든 문자열 테이블 섹션의 인덱스
    base = symtab[5]
    sh_link = _unpack(en + "I", data, base + (40 if bits == 64 else 24), "symtab sh_link")[0]
    if sh_link >= len(raw_sections):
        return
    strtab_off = raw_sections[sh_link][3]
    sym_off, sym_size = symtab[3], symtab[4]
    entsize = 24 if bits == 64 else 16

    for pos in range(sym_off, sym_off + sym_size, entsize):
        if pos + entsize > len(data):
            break
        if bits == 64:
            st_name, st_info = _unpack(en + "IB", data, pos, "심볼")
            st_value = _unpack(en + "Q", data, pos + 8, "심볼")[0]
        else:
            st_name = _unpack(en + "I", data, pos, "심볼")[0]
            st_value = _unpack(en + "I", data, pos + 4, "심볼")[0]
            st_info = data[pos + 12]
        st_type = st_info & 0xF
        if st_type not in (_STT_FUNC, _STT_OBJECT) or st_name == 0:
            continue
        name = _cstr(data, strtab_off + st_name)
        if name:
            kind = "FUNC" if st_type == _STT_FUNC else "OBJECT"
            info.symbols.append(Symbol(name, st_value, kind))


def _parse_elf_segments(data, en, bits, e_phoff, e_phentsize, e_phnum, info):
    """프로그램 헤더(세그먼트)를 읽는다. checksec(NX/RELRO)·ROP 에서 쓴다."""
    if e_phoff == 0 or e_phnum == 0:
        return
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        if bits == 64:
            p_type, p_flags = _unpack(en + "II", data, base, "프로그램 헤더")
            p_offset, p_vaddr = _unpack(en + "QQ", data, base + 8, "프로그램 헤더")
            p_filesz, p_memsz = _unpack(en + "QQ", data, base + 32, "프로그램 헤더")
        else:
            p_type, p_offset, p_vaddr = _unpack(en + "III", data, base, "프로그램 헤더")
            p_filesz, p_memsz, p_flags = _unpack(en + "III", data, base + 16, "프로그램 헤더")
        info.segments.append(Segment(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))


def _parse_elf_dynamic(data, en, bits, info):
    """PT_DYNAMIC 세그먼트에서 .dynamic 태그->값을 읽는다 (DT_NULL 에서 멈춤)."""
    dyn = next((s for s in info.segments if s.type == PT_DYNAMIC), None)
    if dyn is None:
        return
    step = 16 if bits == 64 else 8
    tagfmt = en + ("QQ" if bits == 64 else "II")
    for pos in range(dyn.offset, dyn.offset + dyn.filesz, step):
        if pos + step > len(data):
            break
        tag, val = struct.unpack_from(tagfmt, data, pos)
        if tag == 0:  # DT_NULL
            break
        info.dynamic.setdefault(tag, val)


def _parse_pe(data: bytes) -> BinInfo:
    (e_lfanew,) = _unpack("<I", data, 0x3C, "PE e_lfanew")
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise TransformError("PE 서명(PE\\0\\0)을 찾지 못했습니다")

    coff = e_lfanew + 4
    machine, num_sections = _unpack("<HH", data, coff, "COFF 헤더")
    (size_opt,) = _unpack("<H", data, coff + 16, "COFF 헤더")

    opt = coff + 20
    (magic,) = _unpack("<H", data, opt, "옵션 헤더")
    bits = 64 if magic == 0x20B else 32
    (entry,) = _unpack("<I", data, opt + 16, "옵션 헤더")  # AddressOfEntryPoint (RVA)

    name, arch = _PE_MACHINE.get(machine, (f"unknown(0x{machine:x})", None))
    info = BinInfo(
        fmt="PE", bits=bits, endian="little", machine=name, arch=arch,
        kind="PE32+" if bits == 64 else "PE32", entry=entry,
    )
    # Subsystem·DllCharacteristics 는 PE32/PE32+ 모두 옵션 헤더 오프셋 68/70 에 있다
    # (앞쪽 ImageBase 크기 차이가 뒤쪽에서 상쇄된다). checksec(DEP/ASLR/CFG) 에서 쓴다.
    info.extra["subsystem"] = _unpack("<H", data, opt + 68, "옵션 헤더")[0]
    info.extra["dll_characteristics"] = _unpack("<H", data, opt + 70, "옵션 헤더")[0]

    sect_table = opt + size_opt
    for i in range(num_sections):
        base = sect_table + i * 40
        if base + 40 > len(data):
            break
        raw_name = data[base:base + 8].rstrip(b"\x00")
        vsize, vaddr, rawsize, rawptr = _unpack("<IIII", data, base + 8, "섹션 테이블")
        info.sections.append(
            Section(raw_name.decode("utf-8", "replace"), vaddr, rawptr, vsize, rawsize)
        )
    return info
