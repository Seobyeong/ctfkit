"""rev 명령 + binfmt 파서 테스트.

실제 바이너리 없이도 되도록, 최소한의 ELF64/PE 를 바이트로 직접 만들어 검증한다.
disasm 은 capstone 이 설치돼 있을 때만(importorskip) 돌린다.
"""

import struct

import pytest

from ctfkit import binfmt
from ctfkit.cli import main


def _build_elf64() -> bytes:
    """x86-64 ELF: .text(nop,nop,ret) + main 함수 심볼 하나를 가진 최소 실행 파일."""
    text = b"\x90\x90\xc3"            # nop; nop; ret
    text_addr = 0x401000

    # 섹션 이름 문자열 테이블(.shstrtab)
    shstr = bytearray(b"\x00")
    def _add(s: str) -> int:
        off = len(shstr)
        shstr.extend(s.encode() + b"\x00")
        return off
    n_text = _add(".text")
    n_symtab = _add(".symtab")
    n_strtab = _add(".strtab")
    n_shstrtab = _add(".shstrtab")

    strtab = b"\x00main\x00"          # 심볼 이름 (main 은 오프셋 1)

    # 심볼 테이블: [0]=NULL, [1]=main(FUNC, GLOBAL)
    sym_null = b"\x00" * 24
    sym_main = struct.pack("<IBBHQQ", 1, (1 << 4) | 2, 0, 1, text_addr, len(text))

    # 파일 배치
    ehsize = 64
    text_off = ehsize
    strtab_off = text_off + len(text)
    symtab_off = strtab_off + len(strtab)
    symtab = sym_null + sym_main
    shstr_off = symtab_off + len(symtab)
    shoff = shstr_off + len(shstr)

    # 섹션 헤더 (64바이트씩): NULL, .text, .symtab, .strtab, .shstrtab
    def _sh(name, typ, addr, off, size, link=0, entsize=0):
        return struct.pack("<IIQQQQIIQQ", name, typ, 0, addr, off, size, link, 0, 0, entsize)
    sh = b"".join([
        _sh(0, 0, 0, 0, 0),
        _sh(n_text, 1, text_addr, text_off, len(text)),                 # PROGBITS
        _sh(n_symtab, 2, 0, symtab_off, len(symtab), link=3, entsize=24),  # SYMTAB -> strtab idx 3
        _sh(n_strtab, 3, 0, strtab_off, len(strtab)),                   # STRTAB
        _sh(n_shstrtab, 3, 0, shstr_off, len(shstr)),                   # SHSTRTAB
    ])

    # ELF 헤더
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2, 0x3E, 1,            # e_type=EXEC, e_machine=x86-64, e_version
        text_addr,             # e_entry
        0, shoff,              # e_phoff, e_shoff
        0, ehsize, 0, 0,       # e_flags, e_ehsize, e_phentsize, e_phnum
        64, 5, 4,              # e_shentsize, e_shnum, e_shstrndx(=.shstrtab)
    )
    return ehdr + text + strtab + symtab + bytes(shstr) + sh


def _build_pe64() -> bytes:
    size_opt = 0x70
    dos = bytearray(b"MZ" + b"\x00" * 0x3E)
    struct.pack_into("<I", dos, 0x3C, 0x40)        # e_lfanew -> 0x40
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, size_opt, 0)  # machine=x64, 1 section
    opt = bytearray(size_opt)
    struct.pack_into("<H", opt, 0, 0x20B)          # magic = PE32+
    struct.pack_into("<I", opt, 16, 0x1000)        # AddressOfEntryPoint (RVA)
    section = struct.pack("<8sIIIIIIHHI", b".text", 0x10, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0)
    body = pe_sig + coff + bytes(opt) + section
    blob = bytes(dos) + body
    return blob + b"\x00" * (0x400 - len(blob))    # 섹션 raw 바이트 공간


# --- binfmt 파서 ---

def test_parse_elf64_header_and_symbol():
    info = binfmt.parse(_build_elf64())
    assert info.fmt == "ELF"
    assert info.bits == 64 and info.endian == "little"
    assert info.machine == "x86-64" and info.arch == "x64"
    assert info.entry == 0x401000
    names = {s.name for s in info.sections}
    assert {".text", ".symtab", ".shstrtab"} <= names
    funcs = [s for s in info.symbols if s.kind == "FUNC"]
    assert any(s.name == "main" and s.addr == 0x401000 for s in funcs)


def test_parse_pe64_header_and_section():
    info = binfmt.parse(_build_pe64())
    assert info.fmt == "PE"
    assert info.bits == 64 and info.machine == "x86-64"
    assert info.entry == 0x1000
    assert any(s.name == ".text" for s in info.sections)


def test_parse_rejects_unknown():
    with pytest.raises(binfmt.TransformError):
        binfmt.parse(b"not a binary at all")


def test_section_at_maps_vaddr():
    info = binfmt.parse(_build_elf64())
    sec = info.section_at(0x401000)
    assert sec is not None and sec.name == ".text"
    assert info.section_at(0x999999) is None


# --- rev info ---

def test_info_elf(tmp_path, capsys):
    p = tmp_path / "a.elf"
    p.write_bytes(_build_elf64())
    assert main(["rev", "info", str(p)]) == 0
    out = capsys.readouterr().out
    assert "ELF 64-bit" in out
    assert "x86-64" in out
    assert "0x401000" in out
    assert "main" in out


def test_info_sections_flag(tmp_path, capsys):
    p = tmp_path / "a.elf"
    p.write_bytes(_build_elf64())
    assert main(["rev", "info", str(p), "--sections"]) == 0
    assert ".text" in capsys.readouterr().out


def test_info_pe(tmp_path, capsys):
    p = tmp_path / "a.exe"
    p.write_bytes(_build_pe64())
    assert main(["rev", "info", str(p)]) == 0
    out = capsys.readouterr().out
    assert "PE 64-bit" in out and "x86-64" in out


def test_info_truncated_errors(tmp_path, capsys):
    p = tmp_path / "bad.elf"
    p.write_bytes(b"\x7fELF" + bytes([2, 1, 1]))   # 헤더가 잘림
    assert main(["rev", "info", str(p)]) == 1
    assert "오류" in capsys.readouterr().err


# --- rev disasm (capstone 선택 의존성) ---

def test_disasm_entry(tmp_path, capsys):
    pytest.importorskip("capstone")
    p = tmp_path / "a.elf"
    p.write_bytes(_build_elf64())
    assert main(["rev", "disasm", str(p)]) == 0
    out = capsys.readouterr().out.lower()
    assert "nop" in out and "ret" in out


def test_disasm_without_capstone_message(tmp_path, capsys, monkeypatch):
    # capstone 이 import 안 되는 상황을 흉내 내 안내 메시지를 검증한다
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "capstone":
            raise ImportError("no capstone")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    p = tmp_path / "a.elf"
    p.write_bytes(_build_elf64())
    assert main(["rev", "disasm", str(p)]) == 1
    assert "capstone" in capsys.readouterr().err
