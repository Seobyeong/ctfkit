"""v0.24 탐색 비용 줄이기: guide 안내서, 종료 코드(0 찾음 / 1 못 찾음 / 2 오류), triage --json."""

import hashlib
import io
import json
import zipfile

import pytest

from bench.run import discovery, tokens, used_commands
from bench.tasks import build
from ctfkit import console
from ctfkit.cli import EXIT_ERROR, EXIT_NOT_FOUND, EXIT_OK, build_parser, main
from ctfkit.commands.guide import GUIDE
from ctfkit.gui.schema import _sub_action, build_schema

PNG = b"\x89PNG\r\n\x1a\n"


@pytest.fixture(autouse=True)
def _reset_quiet():
    console.QUIET = False
    yield
    console.QUIET = False


def _run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def _top_commands() -> dict:
    return _sub_action(build_parser()).choices


# --- guide ---

def test_guide_prints_the_text(capsys):
    code, out, err = _run(capsys, "guide")
    assert code == EXIT_OK
    assert out == GUIDE and err == ""


def test_guide_stays_under_500_tokens():
    # 안내서는 짧아야 의미가 있다. 줄을 추가하다 넘치면 다른 줄을 줄여야 한다
    assert tokens(GUIDE) <= 500


def _guide_words() -> set:
    """안내서에 나오는 단어 모음 ("decode|encode" 는 두 단어로 센다)."""
    return {word for chunk in GUIDE.split() for word in chunk.split("|")}


def test_guide_mentions_every_command():
    # 명령을 새로 만들면 안내서에도 한 줄을 넣어야 한다. 별칭(ws)과 guide 자신은 제외
    names = {name for name, parser in _top_commands().items()
             if name != "guide" and name == parser.prog.split()[-1]}
    missing = names - _guide_words()
    assert not missing, f"guide 에 없는 명령: {sorted(missing)} (ctfkit/commands/guide.py 의 GUIDE 에 추가하세요)"


def test_guide_only_names_real_subcommands():
    # 안내서에 적은 "명령 하위명령" 이 실제로 있는지: 없는 이름을 안내하면 에이전트가 헛걸음한다
    parsers = _top_commands()
    for line in GUIDE.splitlines()[3:]:
        body = line.split("  ", 1)[-1].split("#")[0]
        for part in body.split(" | "):
            words = part.split()
            if len(words) < 2 or words[0] not in parsers:
                continue
            sub = _sub_action(parsers[words[0]])
            if sub is None:
                continue
            for name in words[1].split("|"):
                assert name in sub.choices, f"guide: '{words[0]} {name}' 는 없는 하위 명령입니다"


def test_guide_covers_every_benchmark_command(tmp_path):
    # Gate: -h 를 읽지 않고도 벤치마크 과제의 명령을 고를 수 있어야 한다
    used = used_commands(build(tmp_path))
    assert len(used) >= 10
    for command, sub in used:
        lines = [line for line in GUIDE.splitlines()
                 if command in {w for chunk in line.split() for w in chunk.split("|")}]
        assert lines, f"guide 에 '{command}' 가 없습니다"
        if sub:
            assert any(f"{command} " in line and sub in {w for chunk in line.split() for w in chunk.split("|")}
                       for line in lines), f"guide 에 '{command} {sub}' 가 없습니다"


def test_guide_is_much_cheaper_than_reading_help(tmp_path):
    found = discovery(build(tmp_path))
    assert found["guide"]["calls"] == 1
    assert found["guide"]["total"] * 3 < found["help"]["total"]


def test_guide_is_not_a_gui_screen():
    assert "guide" not in [c.name for c in build_schema()]


def test_top_level_help_points_to_guide(capsys):
    with pytest.raises(SystemExit):
        main(["-h"])
    assert "ctfkit guide" in capsys.readouterr().out


# --- 종료 코드 ---

def test_exit_codes_are_three_distinct_values():
    assert (EXIT_OK, EXIT_NOT_FOUND, EXIT_ERROR) == (0, 1, 2)


def test_hash_crack_found_missing_and_error(tmp_path, capsys):
    words = tmp_path / "w.txt"
    words.write_text("apple\nbanana\n", encoding="ascii")
    hit = hashlib.md5(b"banana").hexdigest()
    miss = hashlib.md5(b"cherry").hexdigest()
    assert _run(capsys, "hash", "crack", hit, "-w", str(words))[0] == EXIT_OK
    assert _run(capsys, "hash", "crack", miss, "-w", str(words))[0] == EXIT_NOT_FOUND
    assert _run(capsys, "hash", "crack", "not-hex", "-w", str(words))[0] == EXIT_ERROR
    assert _run(capsys, "hash", "crack", hit, "-w", str(tmp_path / "none.txt"))[0] == EXIT_ERROR


def test_auto_found_and_not_found(capsys):
    assert _run(capsys, "auto", "ZmxhZ3toaX0=")[0] == EXIT_OK
    assert _run(capsys, "auto", "aGVsbG8gd29ybGQ=")[0] == EXIT_NOT_FOUND


def test_bad_input_is_error_not_not_found(capsys):
    code, out, err = _run(capsys, "codec", "decode", "b64", "!!!")
    assert code == EXIT_ERROR and out == "" and err.startswith("오류: ")


def test_missing_file_is_error(capsys):
    assert _run(capsys, "forensic", "id", "no_such_file.bin")[0] == EXIT_ERROR


def test_usage_error_is_also_two():
    with pytest.raises(SystemExit) as stop:
        main(["hash", "crack"])        # 필수 인자 누락 (argparse 가 2 로 끝낸다)
    assert stop.value.code == EXIT_ERROR


def test_triage_exit_code_tells_whether_flag_was_found(tmp_path, capsys):
    with_flag = tmp_path / "a.bin"
    with_flag.write_bytes(b"xx DH{here} yy")
    without = tmp_path / "b.png"
    without.write_bytes(PNG + bytes(100))
    assert _run(capsys, "triage", str(with_flag))[0] == EXIT_OK
    code, out, _ = _run(capsys, "triage", str(without))
    assert code == EXIT_NOT_FOUND
    assert "형식: PNG 이미지" in out     # 못 찾아도 요약은 나온다


# --- triage --json ---

def _png_with_zip(tmp_path, members: dict) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in members.items():
            z.writestr(name, content)
    path = tmp_path / "pic.png"
    path.write_bytes(PNG + bytes(64) + buf.getvalue())
    return str(path)


def test_triage_json_is_one_parseable_line(tmp_path, capsys):
    code, out, err = _run(capsys, "triage", _png_with_zip(tmp_path, {"flag.txt": "DH{json_out}"}), "--json")
    assert code == EXIT_OK and err == ""
    assert len(out.splitlines()) == 1
    data = json.loads(out)
    assert data["flags"] == [{"flag": "DH{json_out}", "where": "ZIP:flag.txt"}]
    assert data["info"]["형식"].startswith("PNG 이미지")
    assert "flag.txt" in data["info"]["ZIP"]


def test_triage_json_without_flag(tmp_path, capsys):
    code, out, _ = _run(capsys, "triage", _png_with_zip(tmp_path, {"a.txt": "nothing here"}), "--json")
    assert code == EXIT_NOT_FOUND
    data = json.loads(out)
    assert data["flags"] == []
    assert "다음" in data["info"]        # 다음에 해 볼 명령도 JSON 안에 들어 있다
