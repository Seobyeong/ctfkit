"""v0.23 호출 수 줄이기: triage 가 여러 분석을 한 번의 호출로 묶는다."""

import base64
import io
import zipfile

import pytest

from ctfkit import binfmt, console
from ctfkit.cli import main
from ctfkit.commands import triage
from ctfkit.commands.pwn import elf_protections
from test_forensic_v014 import _jpeg_with_exif
from test_pwn import _build_elf

PNG = b"\x89PNG\r\n\x1a\n"


@pytest.fixture(autouse=True)
def _reset_quiet():
    console.QUIET = False
    yield
    console.QUIET = False


def _zip(members: dict, compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as z:
        for name, content in members.items():
            z.writestr(name, content)
    return buf.getvalue()


def _write(tmp_path, name, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def _run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


# --- 플래그 찾기 ---

def test_flag_in_plain_bytes(tmp_path, capsys):
    path = _write(tmp_path, "a.bin", b"\x00\x01junk DH{plain_bytes} more\xff")
    code, out, _ = _run(capsys, "triage", path)
    assert code == 0
    assert "플래그: DH{plain_bytes}  [파일 본문]" in out


def test_flag_inside_compressed_zip_after_png(tmp_path, capsys):
    # 압축돼 있어 파일 본문을 그대로 검색해서는 보이지 않는다
    path = _write(tmp_path, "pic.png", PNG + bytes(200) + _zip({"flag.txt": "x\n" * 50 + "DH{zip_after_png}"}))
    _, out, _ = _run(capsys, "triage", path)
    assert "플래그: DH{zip_after_png}  [ZIP:flag.txt]" in out
    assert "형식: PNG 이미지" in out
    assert "숨은 파일: " in out and "ZIP" in out
    assert "ZIP: flag.txt(" in out


def test_encoded_text_in_zip_member_is_decoded(tmp_path, capsys):
    memo = base64.b64encode(b"DH{nested}".hex().encode()).decode()
    path = _write(tmp_path, "memo.png", PNG + bytes(64) + _zip({"memo.txt": memo + "\n"}))
    _, out, _ = _run(capsys, "triage", path)
    assert "플래그: DH{nested}  [ZIP:memo.txt (base64→hex)]" in out


def test_encoded_text_file_is_decoded(tmp_path, capsys):
    path = _write(tmp_path, "note.txt", base64.b64encode(b"DH{text_file}") + b"\n")
    _, out, _ = _run(capsys, "triage", path)
    assert "플래그: DH{text_file}  [파일 본문 (base64)]" in out


def test_flag_in_exif_and_tags_listed(tmp_path, capsys):
    path = _write(tmp_path, "photo.jpg", _jpeg_with_exif())
    _, out, _ = _run(capsys, "triage", path)
    assert "형식: JPEG 이미지" in out
    assert "EXIF: " in out and "Make=" in out


def test_custom_flag_pattern(tmp_path, capsys):
    path = _write(tmp_path, "a.bin", b"xx myctf{custom} DH{ignored}")
    _, out, _ = _run(capsys, "triage", path, "--flag", r"myctf\{.*?\}")
    assert "myctf{custom}" in out and "DH{ignored}" not in out


def test_duplicate_flags_reported_once(tmp_path, capsys):
    # 비압축 ZIP 은 본문 검색과 ZIP 검색 양쪽에서 같은 플래그가 나온다
    path = _write(tmp_path, "a.zip", _zip({"f.txt": "DH{once}"}, zipfile.ZIP_STORED))
    _, out, _ = _run(capsys, "triage", path)
    assert out.count("DH{once}") == 1


# --- 출력 형식 ---

def test_quiet_prints_only_flags(tmp_path, capsys):
    path = _write(tmp_path, "pic.png", PNG + bytes(64) + _zip({"a.txt": "DH{one}", "b.txt": "DH{two}"}))
    code, out, err = _run(capsys, "-q", "triage", path)
    assert code == 0
    assert out.splitlines() == ["DH{one}", "DH{two}"]
    assert err == ""


def test_no_flag_gives_summary_and_next_steps(tmp_path, capsys):
    path = _write(tmp_path, "empty.png", PNG + bytes(300))
    code, out, err = _run(capsys, "triage", path)
    assert code == 1          # v0.24: 플래그를 못 찾으면 1 (요약은 그대로 출력)
    assert "형식: PNG 이미지 (308 바이트)" in out
    assert "다음: forensic lsb" in out
    assert "플래그를 찾지 못했습니다" in err


def test_quiet_without_flag_still_prints_summary(tmp_path, capsys):
    # 플래그가 없으면 요약이 곧 답이다. --quiet 여도 요약은 남고 안내(stderr)만 사라진다
    path = _write(tmp_path, "empty.png", PNG + bytes(300))
    _, out, err = _run(capsys, "-q", "triage", path)
    assert "형식: PNG 이미지" in out and "다음: " in out
    assert err == ""


# --- 실행 파일 ---

def test_elf_summary_has_arch_and_protections(tmp_path, capsys):
    path = _write(tmp_path, "chall", _build_elf(pie=True, nx=True, canary=False, relro="partial"))
    _, out, _ = _run(capsys, "triage", path)
    assert "실행 파일: ELF 64-bit x86-64" in out
    assert "보호 기법: NX 켜짐, PIE 켜짐, Canary 꺼짐, Partial RELRO" in out
    assert "함수: main" in out
    assert "다음: rev disasm" in out


def test_elf_protections_matches_checksec_output(tmp_path, capsys):
    data = _build_elf(pie=False, nx=False, canary=True, relro="full")
    values = dict(elf_protections(binfmt.parse(data)))
    _, out, _ = _run(capsys, "pwn", "checksec", _write(tmp_path, "chall", data))
    for name, value in values.items():
        assert f"{name:<7}: {value}" in out


def test_broken_elf_header_does_not_crash(tmp_path, capsys):
    path = _write(tmp_path, "broken", b"\x7fELF" + b"\xff" * 20 + b" DH{still_found} ")
    code, out, _ = _run(capsys, "triage", path)
    assert code == 0
    assert "DH{still_found}" in out


# --- 상한과 오류 ---

def test_large_zip_member_is_listed_but_not_read(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(triage, "MAX_MEMBER_SIZE", 100)
    path = _write(tmp_path, "a.zip", _zip({"big.txt": "A" * 500 + "DH{too_big}"}))
    _, out, _ = _run(capsys, "triage", path)
    assert "ZIP: big.txt(511)" in out
    assert "DH{too_big}" not in out


def test_long_lists_are_shortened(tmp_path, capsys):
    path = _write(tmp_path, "many.zip", _zip({f"f{i:02d}.txt": "x" for i in range(20)}))
    _, out, _ = _run(capsys, "triage", path)
    assert "외 12개" in out


def test_missing_file_is_short_error(capsys):
    code, out, err = _run(capsys, "triage", "no_such_file.bin")
    assert code == 2
    assert out == "" and err.startswith("오류: ")


def test_bad_flag_regex_is_short_error(tmp_path, capsys):
    code, _, err = _run(capsys, "triage", _write(tmp_path, "a.bin", b"x"), "--flag", "(")
    assert code == 2 and err.startswith("오류: ")
