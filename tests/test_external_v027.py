"""v0.27 외부 도구 연결: external(찾기·실행·상한), triage·start 연결, doctor.

CI 에는 외부 도구가 없거나 버전이 제각각이므로, 파이썬으로 만든 **가짜 실행 파일**만 있는 PATH 로 시험한다.
가짜 도구는 진짜 도구의 출력 형식을 흉내 낸다 (strings -el 은 실제로 UTF-16LE 문자열을 뽑는다).
"""

import io
import os
import sys
import textwrap
import time
import zipfile

import pytest

from ctfkit import console, external
from ctfkit.cli import main
from ctfkit.commands import triage

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


@pytest.fixture(autouse=True)
def _reset_quiet():
    console.QUIET = False
    yield
    console.QUIET = False


@pytest.fixture
def bindir(tmp_path, monkeypatch):
    """가짜 도구만 있는 PATH. 외부 도구를 켠다 (conftest 의 기본은 꺼짐)."""
    path = tmp_path / "bin"
    path.mkdir()
    monkeypatch.delenv("CTFKIT_NO_EXTERNAL", raising=False)
    monkeypatch.setenv("PATH", str(path))
    return path


def make_tool(bindir, name: str, body: str) -> None:
    """파이썬 코드로 가짜 실행 파일을 만든다. 윈도는 .bat 래퍼, 그 밖에는 #! 스크립트."""
    body = "import sys\n" + textwrap.dedent(body)
    if os.name == "nt":
        script = bindir / f"_{name}.py"
        script.write_text(body, encoding="utf-8")
        (bindir / f"{name}.bat").write_text(f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8")
    else:
        exe = bindir / name
        exe.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
        exe.chmod(0o755)


def _run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


FAKE_STRINGS = """
import re
data = open(sys.argv[-1], "rb").read()
if "-el" in sys.argv:
    for m in re.finditer(rb"(?:[\\x20-\\x7e]\\x00){4,}", data):
        print(m.group(0).decode("utf-16-le"))
else:
    for m in re.finditer(rb"[\\x20-\\x7e]{4,}", data):
        print(m.group(0).decode())
"""


# --------------------------------------------------------------- external: 찾기와 실행

def test_find_is_none_when_disabled(bindir, monkeypatch):
    make_tool(bindir, "binwalk", "print('x')")
    assert external.find("binwalk")
    monkeypatch.setenv("CTFKIT_NO_EXTERNAL", "1")
    assert external.find("binwalk") is None
    assert external.missing(["zsteg"]) == []   # 일부러 끈 것이면 설치 안내도 하지 않는다


def test_run_returns_output(bindir):
    make_tool(bindir, "file", "print('PNG image data, 1 x 1')")
    result = external.run("file", ["-b", "x"])
    assert result.ok and result.usable
    assert result.text.strip() == "PNG image data, 1 x 1"


def test_run_missing_tool_is_a_result_not_an_exception(bindir):
    result = external.run("zsteg", ["x"])
    assert not result.ok and not result.usable
    assert result.error == "설치되지 않음"


def test_run_failing_tool_is_not_usable(bindir):
    make_tool(bindir, "exiftool", "print('Error: bad file'); sys.exit(3)")
    result = external.run("exiftool", ["x"])
    assert result.code == 3 and not result.ok and not result.usable


def test_run_hung_tool_times_out(bindir):
    # Gate: 외부 도구가 멈춰도 ctfkit 은 멈추지 않는다. 멈추기 전까지 낸 출력은 쓴다
    make_tool(bindir, "tshark", "print('early', flush=True)\nimport time\ntime.sleep(60)")
    start = time.monotonic()
    result = external.run("tshark", [], timeout=2)
    assert time.monotonic() - start < 15
    assert result.timed_out and not result.ok
    assert "early" in result.text


def test_run_huge_output_is_cut(bindir):
    # Gate: 출력이 끝없이 커져도 상한에서 끊고 돌아온다
    make_tool(bindir, "strings", "while True:\n    sys.stdout.write('A' * 65536)")
    start = time.monotonic()
    result = external.run("strings", [], timeout=30, max_output=256 * 1024)
    assert time.monotonic() - start < 15
    assert result.truncated and not result.timed_out
    assert len(result.output) <= 256 * 1024
    assert result.usable


def test_shell_metacharacters_in_path_are_not_interpreted(bindir, tmp_path):
    make_tool(bindir, "file", "print(sys.argv[-1])")
    odd = str(tmp_path / "a;b&c.png")
    result = external.run("file", ["-b", odd])
    if os.name == "nt":
        # 가짜 도구가 .bat 이다. cmd.exe 가 & 를 명령 구분자로 읽으므로 아예 실행하지 않는다
        assert not result.usable and "특수 문자" in result.error
    else:
        assert result.text.strip() == odd


# --------------------------------------------------------------- triage 연결

def _same_report(a, b):
    return a.items == b.items and a.flags == b.flags


@pytest.mark.parametrize("data", [
    PNG + b"PK\x03\x04" + b"\x00" * 30,
    b"\x7fELF" + b"\x00" * 60,
    b"just text DH{plain}\n",
    b"\x00\x01\x02 unknown",
    b"\xd4\xc3\xb2\xa1" + b"\x00" * 40,
])
def test_no_tools_gives_same_result_as_v026(bindir, tmp_path, monkeypatch, data):
    # Gate: 외부 도구가 하나도 없어도 v0.26(외부 도구 끔)과 같은 결과
    path = tmp_path / "sample.bin"
    path.write_bytes(data)
    pattern = triage.compile_pattern(None)
    without_tools = triage.analyze(str(path), pattern)
    monkeypatch.setenv("CTFKIT_NO_EXTERNAL", "1")
    disabled = triage.analyze(str(path), pattern)
    assert _same_report(without_tools, disabled)


def test_strings_finds_utf16_flag_builtin_misses(bindir, tmp_path):
    # Gate: 도구가 있으면 내장 구현이 못 찾던 것을 더 찾는다. 윈도 프로그램 속 UTF-16LE 문자열
    path = tmp_path / "app.exe"
    path.write_bytes(b"\x00" * 32 + "DH{wide_string_flag}".encode("utf-16-le") + b"\x00" * 32)
    pattern = triage.compile_pattern(None)

    builtin = triage.analyze(str(path), pattern, use_external=False)
    assert builtin.flags == []

    make_tool(bindir, "strings", FAKE_STRINGS)
    report = triage.analyze(str(path), pattern)
    assert report.flags == [("DH{wide_string_flag}", "strings -el (UTF-16)")]


def test_zsteg_flag_is_labeled_with_tool(bindir, tmp_path):
    make_tool(bindir, "zsteg", """
        print("\\x1b[33mb1,rgb,lsb,xy\\x1b[0m .. text: \\"DH{lsb_hidden}\\"")
        print("b2,r,msb,xy .. file: Zip archive data, at least v2.0")
    """)
    path = tmp_path / "pic.png"
    path.write_bytes(PNG)
    report = triage.analyze(str(path), triage.compile_pattern(None))
    assert ("DH{lsb_hidden}", "zsteg") in report.flags
    assert any(key == "zsteg" and "Zip archive" in value for key, value in report.items)


def test_exiftool_keeps_only_interesting_tags(bindir, tmp_path):
    make_tool(bindir, "exiftool", """
        print("ExifToolVersion: 12.76")
        print("FileSize: 72 bytes")
        print("ImageWidth: 1")
        print("Comment: look closer")
        print("Warning: [minor] Trailer data after PNG IEND chunk")
    """)
    path = tmp_path / "pic.png"
    path.write_bytes(PNG)
    report = triage.analyze(str(path), triage.compile_pattern(None))
    value = dict(report.items)["exiftool"]
    assert "Comment=look closer" in value and "Warning=" in value
    assert "FileSize" not in value and "ExifToolVersion" not in value


def test_binwalk_lists_embedded_after_offset_zero(bindir, tmp_path):
    make_tool(bindir, "binwalk", """
        print("")
        print("DECIMAL       HEXADECIMAL     DESCRIPTION")
        print("--------------------------------------------------------------------------------")
        print("0             0x0             PNG image, 1 x 1, 8-bit/color RGBA, non-interlaced")
        print("1234          0x4D2           7-zip archive data, version 0.4")
    """)
    path = tmp_path / "pic.png"
    path.write_bytes(PNG)
    report = triage.analyze(str(path), triage.compile_pattern(None))
    assert dict(report.items)["binwalk"] == "0x4d2 7-zip archive data"


def test_file_used_only_when_builtin_format_unknown(bindir, tmp_path):
    make_tool(bindir, "file", "print('Matlab v4 mat-file')")
    unknown = tmp_path / "x.mat"
    unknown.write_bytes(b"\x00\x01\x02\x03 data")
    png = tmp_path / "x.png"
    png.write_bytes(PNG)
    pattern = triage.compile_pattern(None)
    assert dict(triage.analyze(str(unknown), pattern).items)["형식(file)"] == "Matlab v4 mat-file"
    assert "형식(file)" not in dict(triage.analyze(str(png), pattern).items)


def test_checksec_fills_in_when_builtin_parser_fails(bindir, tmp_path):
    make_tool(bindir, "checksec", """
        print("    Arch:     amd64-64-little")
        print("    RELRO:    Partial RELRO")
        print("    Stack:    No canary found")
        print("    NX:       NX enabled")
        print("    PIE:      No PIE (0x400000)")
    """)
    path = tmp_path / "chall"
    path.write_bytes(b"\x7fELF" + b"\xff" * 20)   # 내장 파서가 읽지 못하는 헤더
    report = triage.analyze(str(path), triage.compile_pattern(None))
    assert dict(report.items)["보호 기법(checksec)"] == "Partial RELRO, No canary found, NX enabled, No PIE"


def test_tshark_protocol_summary(bindir, tmp_path):
    make_tool(bindir, "tshark", """
        print("Protocol Hierarchy Statistics")
        print("eth                                      frames:12 bytes:1500")
        print("  ip                                     frames:12 bytes:1500")
        print("    tcp                                  frames:10 bytes:1300")
        print("      http                               frames:3 bytes:700")
        print("    udp                                  frames:2 bytes:200")
        print("      dns                                frames:2 bytes:200")
    """)
    path = tmp_path / "cap.pcapng"
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
    report = triage.analyze(str(path), triage.compile_pattern(None))
    assert dict(report.items)["프로토콜(tshark)"] == "tcp(10), http(3), udp(2), dns(2)"


def test_broken_tool_output_does_not_break_triage(bindir, tmp_path):
    make_tool(bindir, "binwalk", "sys.stdout.buffer.write(bytes(range(256)) * 10)")
    make_tool(bindir, "exiftool", "print(':::::')")
    path = tmp_path / "pic.png"
    path.write_bytes(PNG)
    report = triage.analyze(str(path), triage.compile_pattern(None))
    assert report.fmt == "PNG 이미지"


def test_text_files_do_not_run_tools(bindir, tmp_path):
    marker = tmp_path / "ran"
    make_tool(bindir, "strings", f"open({str(marker)!r}, 'w').close()")
    path = tmp_path / "note.txt"
    path.write_text("hello world\n")
    triage.analyze(str(path), triage.compile_pattern(None))
    assert not marker.exists()


def test_triage_cli_hints_missing_tools(bindir, tmp_path, capsys):
    path = tmp_path / "pic.png"
    path.write_bytes(PNG)
    code, out, err = _run(capsys, "triage", str(path))
    assert code == 1
    assert "zsteg" in err and "ctfkit doctor" in err
    assert "zsteg" not in out   # 안내는 stderr 로만

    code, out, err = _run(capsys, "-q", "triage", str(path))
    assert err == ""


def test_no_external_option_skips_tools(bindir, tmp_path, capsys):
    make_tool(bindir, "strings", FAKE_STRINGS)
    path = tmp_path / "app.exe"
    path.write_bytes(b"\x00" * 8 + "DH{wide}".encode("utf-16-le"))
    assert _run(capsys, "triage", str(path))[0] == 0
    code, out, err = _run(capsys, "triage", "--no-external", str(path))
    assert code == 1 and "DH{wide}" not in out and "설치하면" not in err


# --------------------------------------------------------------- start 연결

def _zip(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in members.items():
            z.writestr(name, content)
    return buf.getvalue()


def test_start_uses_tools_on_extracted_files(bindir, tmp_path, capsys):
    make_tool(bindir, "zsteg", "print('b1,rgb,lsb,xy .. text: \"DH{from_zsteg}\"')")
    chall = tmp_path / "chall.zip"
    chall.write_bytes(_zip({"stage/pic.png": PNG}))
    code, out, err = _run(capsys, "start", str(chall), "--root", str(tmp_path / "ws"))
    assert code == 0
    assert "DH{from_zsteg}" in out and "zsteg" in out
    notes = (tmp_path / "ws" / "chall" / "notes.md").read_text(encoding="utf-8")
    # 없는 도구는 노트에 남는다 (무엇을 확인하지 못했는지)
    assert "돌리지 못한 도구: strings, exiftool, binwalk" in notes
    assert "설치하면 더 볼 수 있음" in err


def test_start_without_tools_matches_disabled(bindir, tmp_path, capsys, monkeypatch):
    chall = tmp_path / "chall.zip"
    chall.write_bytes(_zip({"a/pic.png": PNG, "b/msg.txt": "REh7bmVzdGVkfQ=="}))
    code1, out1, _ = _run(capsys, "start", str(chall), "--root", str(tmp_path / "w1"))
    monkeypatch.setenv("CTFKIT_NO_EXTERNAL", "1")
    code2, out2, _ = _run(capsys, "start", str(chall), "--root", str(tmp_path / "w2"))
    assert code1 == code2 == 0
    assert out1.replace("w1", "w2") == out2


# --------------------------------------------------------------- doctor

def test_doctor_lists_every_tool(bindir, capsys):
    make_tool(bindir, "binwalk", "print('x')")
    code, out, err = _run(capsys, "doctor")
    assert code == 0
    for name in external.TOOL_NAMES:
        assert name in out
    assert "[O] binwalk" in out
    assert "[ ] zsteg" in out and "없으면:" in out
    assert "apt install" in err


def test_doctor_says_when_disabled(capsys):
    code, out, err = _run(capsys, "doctor")   # conftest 가 CTFKIT_NO_EXTERNAL=1
    assert code == 0 and "CTFKIT_NO_EXTERNAL" in err
