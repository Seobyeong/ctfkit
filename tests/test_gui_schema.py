"""화면 구조 자동 생성 테스트. 새 명령을 추가해도 이 테스트들이 그대로 적용된다."""

import argparse

import pytest

from ctfkit import registry
from ctfkit.cli import build_parser
from ctfkit.gui.schema import InputProblem, build_argv, build_schema


def _command(name):
    return next(c for c in build_schema() if c.name == name)


def _action(command, name):
    return next(a for a in command.actions if a.name == name)


def _sample_value(f):
    if f.kind == "check":
        return True
    if f.value_type is not None:
        return "1"
    if f.choices:
        return f.choices[0]
    return f"sample-{f.dest}"


def _all_pairs():
    return [(c, a) for c in build_schema() for a in c.actions]


def test_every_command_appears_once_without_ui_or_alias():
    names = [c.name for c in build_schema()]
    assert names == ["triage", "auto", "codec", "base", "crack", "crypto", "rsa", "hash", "rev", "pwn", "forensic", "web", "jwt", "workspace"]


@pytest.mark.parametrize("command,action", _all_pairs(), ids=lambda x: getattr(x, "name", None))
def test_generated_argv_is_accepted_by_real_parser(command, action):
    # 모든 항목을 채운 입력이 실제 argparse 를 통과해야 한다 (새 명령도 자동으로 검사됨)
    fields = [*command.shared, *action.fields]
    argv, _ = build_argv(command, action, {f.dest: _sample_value(f) for f in fields})
    args = build_parser().parse_args(argv)
    assert callable(args.func)


@pytest.mark.parametrize("command,action", _all_pairs(), ids=lambda x: getattr(x, "name", None))
def test_filled_values_reach_parsed_args(command, action):
    fields = [*command.shared, *action.fields]
    argv, _ = build_argv(command, action, {f.dest: _sample_value(f) for f in fields})
    args = build_parser().parse_args(argv)
    for f in fields:
        if f.stdin or f.kind == "check" or f.value_type is not None:
            continue
        parsed = getattr(args, f.dest)
        parsed = " ".join(parsed) if isinstance(parsed, list) else parsed
        assert parsed == _sample_value(f), f.dest


def test_new_command_without_hints_gets_a_working_form():
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest="command", required=True)
    p = subs.add_parser("pwn", help="새로 추가한 기능 (설명)")
    p.add_argument("target", help="대상 주소")
    p.add_argument("-f", "--file", help="입력 파일")
    p.add_argument("--port", type=int, default=80, help="포트 번호 (기본 80)")
    p.add_argument("--mode", choices=["fast", "slow"], default="fast", help="방식")
    p.add_argument("--verbose", action="store_true", help="자세히")
    p.add_argument("--tag", action="append", help="태그")

    command = build_schema(parser, hints={})[0]
    assert (command.name, command.label, command.desc) == ("pwn", "pwn", "새로 추가한 기능 (설명)")
    kinds = {f.dest: (f.label, f.kind) for f in command.actions[0].fields}
    assert kinds == {
        "target": ("대상 주소", "entry"),
        "file": ("입력 파일", "file"),
        "port": ("포트 번호", "number"),
        "mode": ("방식", "combo"),
        "verbose": ("자세히", "check"),
        "tag": ("태그", "lines"),
    }
    argv, stdin = build_argv(command, command.actions[0],
                             {"target": "host", "port": "8080", "verbose": True, "tag": "a\nb"})
    assert argv == ["pwn", "--port=8080", "--verbose", "--tag=a", "--tag=b", "host"]
    assert stdin is None


def test_new_transform_appears_in_dropdown(monkeypatch):
    class Atbash(registry.Transform):
        name = "atbash"

    original = registry.all_transforms()
    monkeypatch.setattr(registry, "all_transforms", lambda: [*original, Atbash()])
    field = next(f for f in _action(_command("codec"), "decode").fields if f.dest == "transform")
    assert "atbash" in field.choices


def test_crack_lists_only_keyed_transforms():
    field = next(f for f in _command("crack").actions[0].fields if f.dest == "transform")
    assert set(field.choices) == {"caesar", "vigenere", "xor"}


def test_action_hint_overrides_only_that_action():
    hash_cmd = _command("hash")
    sum_algo = next(f for f in _action(hash_cmd, "sum").fields if f.dest == "algo")
    crack_algo = next(f for f in _action(hash_cmd, "crack").fields if f.dest == "algo")
    assert sum_algo.default == "sha256"
    assert crack_algo.default == ""


def test_text_input_goes_through_stdin():
    command = _command("auto")
    argv, stdin = build_argv(command, command.actions[0], {"data": "-looks-like-option"})
    assert argv == ["auto"]
    assert stdin == "-looks-like-option"


def test_file_takes_priority_over_text():
    command = _command("auto")
    argv, stdin = build_argv(command, command.actions[0], {"data": "ignored", "file": "x.bin"})
    assert argv == ["auto", "--file=x.bin"]
    assert stdin is None


def test_missing_input_is_reported():
    command = _command("auto")
    with pytest.raises(InputProblem, match="파일을 선택"):
        build_argv(command, command.actions[0], {"data": "  "})


def test_missing_required_field_is_reported():
    command = _command("hash")
    with pytest.raises(InputProblem, match="해시값"):
        build_argv(command, _action(command, "id"), {"digest": ""})


def test_bad_number_is_reported():
    command = _command("auto")
    with pytest.raises(InputProblem, match="숫자"):
        build_argv(command, command.actions[0], {"data": "x", "depth": "many"})


def test_default_values_are_not_repeated_in_command():
    command = _command("auto")
    fields = {f.dest: f.default for f in command.actions[0].fields}
    argv, _ = build_argv(command, command.actions[0], {**fields, "data": "x"})
    assert argv == ["auto"]


def test_dash_values_are_not_taken_as_options():
    command = _command("hash")
    argv, _ = build_argv(command, _action(command, "id"), {"digest": "-abc"})
    assert build_parser().parse_args(argv).digest == "-abc"
    argv, _ = build_argv(command, _action(command, "hmac"), {"algo": "md5", "key": "-k", "data": "m"})
    assert build_parser().parse_args(argv).key == "-k"


def test_shared_option_comes_before_action():
    command = _command("workspace")
    argv, _ = build_argv(command, _action(command, "new"), {"root": "/tmp/x", "name": "web-100"})
    assert argv == ["workspace", "--root=/tmp/x", "new", "web-100"]
