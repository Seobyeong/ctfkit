"""v0.19 출력 효율 테스트: --quiet, emit_lines(limit/grep)."""

import pytest

from ctfkit import console
from ctfkit.cli import main
from ctfkit.registry import TransformError


@pytest.fixture(autouse=True)
def _reset_quiet():
    # 각 테스트는 조용히 모드 off 에서 시작한다 (main 이 바꿔도 되돌린다)
    console.QUIET = False
    yield
    console.QUIET = False


# --- emit_lines ---

def test_emit_lines_limit_caps_and_notes(capsys):
    shown = console.emit_lines([f"line{i}" for i in range(10)], limit=3)
    cap = capsys.readouterr()
    assert shown == 3
    assert cap.out.splitlines() == ["line0", "line1", "line2"]
    assert "7개 더 있음" in cap.err          # 잘린 개수 안내는 stderr


def test_emit_lines_no_limit_shows_all(capsys):
    shown = console.emit_lines([f"l{i}" for i in range(5)], limit=0)
    assert shown == 5
    assert capsys.readouterr().err == ""     # 전체 출력이면 안내 없음


def test_emit_lines_grep_filters(capsys):
    shown = console.emit_lines(["apple", "banana", "grape"], grep="a.*e")
    assert shown == 2
    assert capsys.readouterr().out.splitlines() == ["apple", "grape"]


def test_emit_lines_invalid_grep_raises():
    with pytest.raises(TransformError):
        console.emit_lines(["x"], grep="(")


def test_emit_lines_quiet_keeps_short_truncation_note(capsys):
    # v0.21: 잘렸다는 사실은 결과 해석에 필요하므로 --quiet 여도 짧게 알린다
    console.QUIET = True
    console.emit_lines(["a", "b", "c"], limit=1)
    cap = capsys.readouterr()
    assert cap.out.splitlines() == ["a"]
    assert cap.err == "... +2\n"


# --- --quiet 전역 플래그 (stderr 안내 억제, stdout 답은 유지) ---

JWT_NONE = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."


def test_quiet_suppresses_stderr_keeps_stdout(capsys):
    assert main(["-q", "jwt", "decode", JWT_NONE]) == 0
    cap = capsys.readouterr()
    assert '"user":"admin"' in cap.out         # 답(stdout)은 남는다 (v0.21: 들여쓰기 없는 JSON)
    assert cap.err == ""                        # 안내(stderr)는 사라진다


def test_without_quiet_shows_stderr(capsys):
    assert main(["jwt", "decode", JWT_NONE]) == 0
    cap = capsys.readouterr()
    assert '"user": "admin"' in cap.out
    assert cap.err != ""                        # 기본값은 안내를 보여 준다


# --- forensic strings --limit / --grep (CLI) ---

def _sample(tmp_path):
    p = tmp_path / "s.bin"
    p.write_bytes(b"hello world\x00\x00secret_flag\x00\x00DH{abc}\x00junkjunkjunk")
    return str(p)


def test_strings_limit_cli(tmp_path, capsys):
    main(["forensic", "strings", _sample(tmp_path), "--limit", "2"])
    cap = capsys.readouterr()
    assert len(cap.out.splitlines()) == 2
    assert "더 있음" in cap.err


def test_strings_grep_cli(tmp_path, capsys):
    main(["forensic", "strings", _sample(tmp_path), "--grep", "flag|DH"])
    out = capsys.readouterr().out
    assert "secret_flag" in out and "DH{abc}" in out
    assert "hello world" not in out
