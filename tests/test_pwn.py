"""pwn 명령 테스트 (checksec / cyclic / rop).

checksec 는 보호 기법 조합별로 ELF 를 직접 만들어 통합 검증한다(binfmt 세그먼트·dynamic
파싱까지 함께 탄다). rop 는 capstone 이 있을 때만 돌린다.
"""

import struct
import sys

import pytest

from ctfkit import binfmt
from ctfkit.cli import main
from ctfkit.commands.pwn import de_bruijn


def _build_elf(text=b"\x90\x90\xc3", *, pie=True, nx=True, canary=True, relro="full"):
    """보호 기법 조합을 지정해 x86-64 ELF 를 만든다 (프로그램 헤더·dynamic 포함)."""
    base = 0x400000

    # 심볼 이름 문자열 테이블
    strtab = bytearray(b"\x00")
    main_off = len(strtab); strtab += b"main\x00"
    chk_off = len(strtab); strtab += b"__stack_chk_fail\x00"
    strtab = bytes(strtab)

    # 섹션 이름 문자열 테이블
    shstr = bytearray(b"\x00")
    def _sn(s):
        off = len(shstr); shstr.extend(s.encode() + b"\x00"); return off
    n_text, n_symtab, n_strtab, n_shstrtab = (_sn(".text"), _sn(".symtab"),
                                              _sn(".strtab"), _sn(".shstrtab"))

    # dynamic: full RELRO 면 BIND_NOW 를 넣고, 항상 DT_NULL 로 끝낸다
    dyn = b""
    if relro == "full":
        dyn += struct.pack("<QQ", binfmt.DT_BIND_NOW, 0)
    dyn += struct.pack("<QQ", 0, 0)

    # 심볼: NULL, main, (canary 면) __stack_chk_fail(undef)
    syms = b"\x00" * 24
    syms += struct.pack("<IBBHQQ", main_off, (1 << 4) | 2, 0, 1, base, len(text))
    if canary:
        syms += struct.pack("<IBBHQQ", chk_off, (1 << 4) | 2, 0, 0, 0, 0)

    phnum = 3 + (1 if relro in ("full", "partial") else 0)
    ehsize, phentsize = 64, 56
    phoff = ehsize
    text_off = phoff + phnum * phentsize
    strtab_off = text_off + len(text)
    symtab_off = strtab_off + len(strtab)
    dyn_off = symtab_off + len(syms)
    shstr_off = dyn_off + len(dyn)
    shoff = shstr_off + len(shstr)
    total = shoff + 5 * 64

    # 프로그램 헤더
    def _ph(ptype, flags, off, vaddr, sz):
        # type,flags,offset,vaddr,paddr,filesz,memsz,align = 56바이트
        return struct.pack("<IIQQQQQQ", ptype, flags, off, vaddr, vaddr, sz, sz, 0)
    phdrs = _ph(binfmt.PT_LOAD, 5, 0, base, total)                     # R+X, 파일 전체
    phdrs += _ph(binfmt.PT_GNU_STACK, 6 if nx else 7, 0, 0, 0)         # X 없으면 NX 켜짐
    phdrs += _ph(binfmt.PT_DYNAMIC, 6, dyn_off, base + dyn_off, len(dyn))
    if relro in ("full", "partial"):
        phdrs += _ph(binfmt.PT_GNU_RELRO, 4, dyn_off, base + dyn_off, len(dyn))

    # 섹션 헤더
    def _sh(name, typ, addr, off, size, link=0, entsize=0):
        return struct.pack("<IIQQQQIIQQ", name, typ, 0, addr, off, size, link, 0, 0, entsize)
    sh = b"".join([
        _sh(0, 0, 0, 0, 0),
        _sh(n_text, 1, base + text_off, text_off, len(text)),
        _sh(n_symtab, 2, 0, symtab_off, len(syms), link=3, entsize=24),
        _sh(n_strtab, 3, 0, strtab_off, len(strtab)),
        _sh(n_shstrtab, 3, 0, shstr_off, len(shstr)),
    ])

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        3 if pie else 2, 0x3E, 1,       # e_type(DYN=PIE / EXEC), x86-64
        base + text_off,                # e_entry
        phoff, shoff,
        0, ehsize, phentsize, phnum,
        64, 5, 4,
    )
    blob = ehdr + phdrs + text + strtab + syms + dyn + bytes(shstr) + sh
    assert len(blob) == total
    return blob


# --- binfmt: 세그먼트·dynamic 파싱 ---

def test_binfmt_parses_segments_and_dynamic():
    info = binfmt.parse(_build_elf(relro="full"))
    types = {s.type for s in info.segments}
    assert binfmt.PT_GNU_STACK in types
    assert binfmt.PT_DYNAMIC in types
    assert binfmt.PT_GNU_RELRO in types
    assert binfmt.DT_BIND_NOW in info.dynamic


# --- checksec ---

def test_checksec_all_on(tmp_path, capsys):
    p = tmp_path / "secure"
    p.write_bytes(_build_elf(pie=True, nx=True, canary=True, relro="full"))
    assert main(["pwn", "checksec", str(p)]) == 0
    out = capsys.readouterr().out
    assert "NX" in out and "켜짐" in out
    assert "PIE    : 켜짐" in out
    assert "Canary : 켜짐" in out
    assert "Full RELRO" in out


def test_checksec_all_off(tmp_path, capsys):
    p = tmp_path / "vuln"
    p.write_bytes(_build_elf(pie=False, nx=False, canary=False, relro="none"))
    assert main(["pwn", "checksec", str(p)]) == 0
    out = capsys.readouterr().out
    assert "꺼짐(실행 가능 스택)" in out
    assert "PIE    : 꺼짐 (No PIE)" in out
    assert "Canary : 꺼짐" in out
    assert "No RELRO" in out


def test_checksec_partial_relro(tmp_path, capsys):
    p = tmp_path / "part"
    p.write_bytes(_build_elf(relro="partial"))
    assert main(["pwn", "checksec", str(p)]) == 0
    assert "Partial RELRO" in capsys.readouterr().out


def test_checksec_pe(tmp_path, capsys):
    # 직접 만든 PE 로 검사한다. 예전에는 sys.executable 을 넣었는데, 리눅스의 파이썬은 ELF 라서
    # Windows 에서만 통과했다 (CI 의 ubuntu 작업이 v0.13 부터 실패한 원인).
    from test_rev import _build_pe64

    p = tmp_path / "chall.exe"
    p.write_bytes(_build_pe64())
    assert main(["pwn", "checksec", str(p)]) == 0
    out = capsys.readouterr().out
    assert "PE" in out
    assert "DllCharacteristics" in out and "DEP" in out


@pytest.mark.skipif(sys.platform != "win32", reason="파이썬 실행 파일이 PE 인 Windows 에서만 의미가 있다")
def test_checksec_real_windows_binary(capsys):
    assert main(["pwn", "checksec", sys.executable]) == 0
    assert "DllCharacteristics" in capsys.readouterr().out


# --- cyclic ---

def test_cyclic_generate_length(capsys):
    assert main(["pwn", "cyclic", "100"]) == 0
    out = capsys.readouterr().out.strip()
    assert len(out) == 100


def test_cyclic_subsequences_unique():
    # de Bruijn: 길이 4 부분열이 모두 서로 다르게 나와야 오프셋 역산이 가능하다
    pat = de_bruijn(b"abcdefghijklmnopqrstuvwxyz", 4)[:1000]
    subs = [bytes(pat[i:i + 4]) for i in range(len(pat) - 3)]
    assert len(subs) == len(set(subs))


def test_cyclic_lookup_roundtrip(capsys):
    assert main(["pwn", "cyclic", "200"]) == 0
    pat = capsys.readouterr().out.strip()
    value = pat[50:54]                      # 오프셋 50 의 4바이트
    assert main(["pwn", "cyclic", "--lookup", value]) == 0
    assert capsys.readouterr().out.strip() == "50"


def test_cyclic_lookup_hex(capsys):
    # 크래시 때 레지스터에 담긴 값(리틀엔디언)을 0x.. 로 넣어 오프셋을 찾는다
    assert main(["pwn", "cyclic", "200"]) == 0
    pat = capsys.readouterr().out.strip().encode()
    want = pat[16:20]
    hexval = "0x" + int.from_bytes(want, "little").to_bytes(4, "big").hex()
    assert main(["pwn", "cyclic", "--lookup", hexval]) == 0
    assert capsys.readouterr().out.strip() == "16"


def test_cyclic_length_too_large(capsys):
    assert main(["pwn", "cyclic", "100", "-n", "1"]) == 2   # n=1 이면 최대 26
    assert "넘습니다" in capsys.readouterr().err


def test_cyclic_needs_length_or_lookup(capsys):
    assert main(["pwn", "cyclic"]) == 2
    assert "길이를 주거나" in capsys.readouterr().err


# --- rop (capstone 선택 의존성) ---

def test_rop_finds_pop_rdi(tmp_path, capsys):
    pytest.importorskip("capstone")
    # pop rdi; ret  (5f c3)  +  pop rax; ret  (58 c3)
    p = tmp_path / "g.elf"
    p.write_bytes(_build_elf(text=b"\x5f\xc3\x58\xc3"))
    assert main(["pwn", "rop", str(p), "-f", "pop rdi"]) == 0
    out = capsys.readouterr().out
    assert "pop rdi" in out and "ret" in out


def test_rop_filter_no_match(tmp_path, capsys):
    pytest.importorskip("capstone")
    p = tmp_path / "g.elf"
    p.write_bytes(_build_elf(text=b"\x5f\xc3"))
    assert main(["pwn", "rop", str(p), "-f", "syscall"]) == 1
    assert "없습니다" in capsys.readouterr().err
