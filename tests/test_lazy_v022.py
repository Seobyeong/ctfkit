"""v0.22 실행 시간 줄이기: 실행할 명령의 모듈만 불러온다 (지연 로딩)."""

import pkgutil
import subprocess
import sys

import pytest

from ctfkit import cli, commands, registry, transforms
from ctfkit.cli import build_parser, main


def _command_names():
    """전체 파서에 등록된 모든 명령 이름 (별칭 포함)."""
    for action in build_parser()._actions:
        if hasattr(action, "choices") and action.choices and action.dest == "command":
            return sorted(action.choices)
    raise AssertionError("서브커맨드를 찾지 못함")


def test_module_names_matches_pkgutil():
    # 직접 만든 목록이 pkgutil 과 같은 이름·같은 순서여야 한다 (auto 의 변환 시도 순서가 여기에 달렸다)
    for package in (commands, transforms):
        expected = [m.name for m in pkgutil.iter_modules(package.__path__)]
        assert registry.module_names(package) == expected


@pytest.mark.parametrize("command", _command_names())
def test_every_command_resolves_to_one_module(command):
    # 명령 이름이 파일 이름과 다르면 commands.ALIASES 에 적어야 한다. 빠지면 여기서 걸린다.
    module = cli._module_for(command)
    assert module is not None, f"{command}: commands.ALIASES 에 '{command}': '<모듈 이름>' 을 추가하세요"


def test_requested_command_skips_global_options():
    assert cli._requested_command(["-q", "hash", "id", "abc"]) == "hash"
    assert cli._requested_command(["--quiet", "auto", "-n", "3"]) == "auto"
    assert cli._requested_command(["-h"]) is None
    assert cli._requested_command([]) is None


def test_module_for_rejects_unknown_and_private_names():
    assert cli._module_for("nosuch") is None
    assert cli._module_for("__init__") is None
    assert cli._module_for("../web") is None


def test_unknown_command_still_lists_all_commands(capsys):
    with pytest.raises(SystemExit):
        main(["nosuch"])
    err = capsys.readouterr().err
    assert "invalid choice" in err and "forensic" in err and "web" in err


def test_module_name_that_is_not_a_command_falls_back(capsys):
    # 'hashes' 는 파일 이름이지 명령 이름이 아니다 → 전체 목록으로 안내해야 한다
    with pytest.raises(SystemExit):
        main(["hashes", "id", "abc"])
    assert "jwt" in capsys.readouterr().err


def _imported_after(*argv):
    code = (
        "import sys; from ctfkit.cli import main; main(sys.argv[1:]); "
        "print(chr(10).join(m for m in sys.modules if m.startswith(('ctfkit.commands.', 'urllib.request', 'tkinter'))))"
    )
    out = subprocess.run([sys.executable, "-c", code, *argv], capture_output=True, text=True, encoding="utf-8")
    return set(out.stdout.split())


def test_running_one_command_imports_only_its_module():
    loaded = _imported_after("-q", "hash", "sum", "md5", "x")
    assert "ctfkit.commands.hashes" in loaded
    assert not {"ctfkit.commands.web", "ctfkit.commands.forensic", "urllib.request", "tkinter"} & loaded


def test_alias_command_runs_through_fast_path():
    loaded = _imported_after("-q", "base", "255", "--to", "2")
    assert loaded == {"ctfkit.commands.numbase", "11111111"}


def test_cyclic_does_not_import_binfmt():
    code = "import sys; from ctfkit.cli import main; main(['-q','pwn','cyclic','-l','faaa']); print('ctfkit.binfmt' in sys.modules, 'shutil' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, encoding="utf-8")
    assert out.stdout.split() == ["20", "False", "False"]


def test_help_still_wraps_to_terminal_width(monkeypatch, capsys):
    # shutil 없이 직접 구한 폭이 COLUMNS 를 따르는지
    monkeypatch.setenv("COLUMNS", "50")
    with pytest.raises(SystemExit):
        main(["web", "send", "-h"])
    out = capsys.readouterr().out
    assert out and max(len(line) for line in out.splitlines()) <= 50


def test_extract_strings_matches_byte_loop():
    # 정규식 구현이 예전의 바이트 반복 구현과 같은 결과를 내는지 무작위 데이터로 대조한다
    import random

    from ctfkit.commands.forensic import extract_strings

    def reference(data, min_len):
        results, cur, start = [], bytearray(), 0
        for i, b in enumerate(data):
            if 0x20 <= b <= 0x7E:
                if not cur:
                    start = i
                cur.append(b)
            else:
                if len(cur) >= min_len:
                    results.append((start, cur.decode("ascii")))
                cur = bytearray()
        if len(cur) >= min_len:
            results.append((start, cur.decode("ascii")))
        return results

    rng = random.Random(22)
    for min_len in (1, 4, 8):
        data = bytes(rng.choice(b"abcXYZ 09{}~\x00\x1f\x7f\xff\n") for _ in range(5000))
        assert extract_strings(data, min_len) == reference(data, min_len)
    assert extract_strings(b"", 4) == []
    assert extract_strings(b"tail", 4) == [(0, "tail")]
