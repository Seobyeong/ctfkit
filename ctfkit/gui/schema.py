"""argparse 정의를 읽어 화면 구조를 만들고, 입력값을 다시 명령줄 인자로 바꾼다.

화면 항목을 따로 적지 않으므로 commands/ 에 명령이나 옵션을 추가하면 화면에도 자동으로 나타난다.
라벨·순서·입력 방식을 다듬고 싶으면 명령 모듈에 GUI_HINTS 를 둔다 (없어도 동작한다):

    GUI_HINTS = {
        "hash": {                              # 서브커맨드 이름
            "label": "해시",                    # 사이드바 이름 (기본: 명령 이름)
            "order": 40,                       # 사이드바 순서 (기본: 맨 뒤)
            "group": "암호·인코딩",              # 사이드바 묶음 이름 (기본: "기타")
            "desc": "...",                     # 화면 설명 (기본: argparse help)
            "hidden": False,                   # True 면 화면에서 뺀다
            "actions": {"id": "판별"},          # 하위 명령 라벨. 적은 순서대로 먼저 표시
            "examples": {                      # "예시 채우기" 로 넣을 값. 키는 하위 명령 이름
                "id": {"digest": "5f4d..."},   #   (하위 명령이 없는 명령은 "" 를 키로 쓴다)
            },
            "fields": {
                "algo": {"label": "알고리즘", "suggest": ["md5"]},
                "crack.algo": {"default": ""}, # "하위 명령.옵션" 은 그 하위 명령에만 적용
            },
        },
    }

fields 에 쓸 수 있는 키: label, kind, default, choices, suggest. default·choices·suggest 는 함수여도 된다.
kind: text(여러 줄) / lines(한 줄에 값 하나) / entry / number / combo / check / file / save / dir
"""

import argparse
import importlib
import pkgutil
from dataclasses import dataclass, field as dc_field

from ctfkit import commands

# 옵션 이름만으로 입력 방식을 정하는 관례. 새 명령도 같은 이름을 쓰면 파일 선택 버튼 등이 자동으로 붙는다.
_KIND_BY_DEST = {"file": "file", "words": "file", "cookies": "file", "dump": "save", "root": "dir"}
_LAST_ORDER = 1000


class InputProblem(ValueError):
    """사용자에게 보여줄 입력값 문제 (필수 항목 누락, 숫자 형식 오류 등).

    dest 는 문제가 된 항목 이름이다. 화면이 그 입력 칸을 강조하고 커서를 옮기는 데 쓴다.
    """

    def __init__(self, message: str, dest: str | None = None):
        super().__init__(message)
        self.dest = dest


@dataclass
class Field:
    dest: str
    label: str
    kind: str
    option: str | None        # None 이면 위치 인자
    required: bool = False
    default: object = ""      # 화면에 미리 채울 값
    arg_default: object = None   # argparse 기본값. 같은 값이면 명령줄에 넣지 않는다
    choices: list | None = None
    editable: bool = False    # combo 에 목록 밖의 값을 직접 입력할 수 있는가
    multiple: bool = False    # append / nargs='+': 한 줄이 값 하나
    value_type: object = None
    stdin: bool = False       # 인자 대신 stdin 으로 넘길 입력
    help: str = ""            # argparse help 전체. 라벨에 마우스를 올리면 보여 준다


@dataclass
class Action:
    name: str | None          # 하위 명령이 없는 명령(auto 등)은 None
    label: str
    fields: list = dc_field(default_factory=list)
    example: dict = dc_field(default_factory=dict)   # "예시 채우기" 로 넣을 값 {항목 이름: 값}


@dataclass
class Command:
    name: str
    label: str
    desc: str
    order: int
    actions: list
    shared: list              # 하위 명령 앞에 오는 공통 옵션 (workspace --root 등)
    group: str = "기타"        # 사이드바에서 함께 묶어 보여 줄 분야 이름


def _resolve(value):
    return value() if callable(value) else value


def _sub_action(parser):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action
    return None


def _helps(sub) -> dict:
    return {a.dest: a.help or "" for a in sub._choices_actions}


def _clean_help(text: str) -> str:
    # "최대 단계 수 (기본 5)" -> "최대 단계 수"
    return (text or "").split(" (")[0].strip()


def _long_option(action) -> str:
    longs = [o for o in action.option_strings if o.startswith("--")]
    return longs[0] if longs else action.option_strings[0]


def _make_field(action, hints: dict, action_name: str | None) -> Field | None:
    if isinstance(action, (argparse._HelpAction, argparse._VersionAction, argparse._SubParsersAction)):
        return None
    if action.help == argparse.SUPPRESS:
        return None

    hint = {**hints.get(action.dest, {}), **hints.get(f"{action_name}.{action.dest}", {})}
    is_option = bool(action.option_strings)
    is_flag = action.nargs == 0
    multiple = isinstance(action, argparse._AppendAction) or action.nargs in ("+", "*")
    # 위치 인자의 기본값이 '-' 면 stdin 입력 (console.read_input 규칙)
    stdin = not is_option and action.default == "-"
    required = action.required if is_option else action.nargs in (None, "+")

    suggest = _resolve(hint.get("suggest"))
    choices = _resolve(hint.get("choices")) or (list(action.choices) if action.choices else None)

    kind = hint.get("kind")
    if kind is None:
        if is_flag:
            kind = "check"
        elif choices or suggest:
            kind = "combo"
        elif stdin:
            kind = "text"
        elif action.dest in _KIND_BY_DEST:
            kind = _KIND_BY_DEST[action.dest]
        elif multiple:
            kind = "lines"
        elif action.type in (int, float):
            kind = "number"
        else:
            kind = "entry"

    arg_default = action.default
    if "default" in hint:
        default = _resolve(hint["default"])
    elif is_flag:
        default = bool(action.default)
    elif stdin or action.default in (None, argparse.SUPPRESS) or multiple:
        default = ""
    else:
        default = action.default

    return Field(
        dest=action.dest,
        label=hint.get("label") or _clean_help(action.help) or (
            action.option_strings[-1].lstrip("-") if is_option else action.dest),
        kind=kind,
        option=_long_option(action) if is_option else None,
        required=required,
        default=default,
        arg_default=arg_default,
        choices=suggest or choices,
        editable=bool(suggest),
        multiple=multiple,
        value_type=action.type if action.type in (int, float) else None,
        stdin=stdin,
        help=action.help or "",
    )


def _fields(parser, hints: dict, action_name: str | None) -> list:
    made = (_make_field(a, hints, action_name) for a in parser._actions)
    return [f for f in made if f is not None]


def _load_hints() -> dict:
    hints = {}
    for module in pkgutil.iter_modules(commands.__path__):
        loaded = importlib.import_module(f"{commands.__name__}.{module.name}")
        hints.update(getattr(loaded, "GUI_HINTS", {}))
    return hints


def _make_command(name: str, parser, help_text: str, hint: dict) -> Command:
    field_hints = hint.get("fields", {})
    action_labels = hint.get("actions", {})
    examples = hint.get("examples", {})
    sub = _sub_action(parser)
    if sub is None:
        actions = [Action(None, hint.get("label", name), _fields(parser, field_hints, None),
                          dict(examples.get("", {})))]
        shared = []
    else:
        helps = _helps(sub)
        names = list(dict.fromkeys(sub.choices))
        names.sort(key=lambda n: list(action_labels).index(n) if n in action_labels else len(action_labels))
        actions = [
            Action(n, action_labels.get(n) or _clean_help(helps.get(n)) or n,
                   _fields(sub.choices[n], field_hints, n), dict(examples.get(n, {})))
            for n in names
        ]
        shared = _fields(parser, field_hints, None)
    return Command(
        name=name,
        label=hint.get("label", name),
        desc=hint.get("desc", help_text),
        order=hint.get("order", _LAST_ORDER),
        actions=actions,
        shared=shared,
        group=hint.get("group", "기타"),
    )


def build_schema(parser=None, hints: dict | None = None) -> list:
    """ArgumentParser 를 읽어 화면에 표시할 Command 목록을 만든다."""
    if parser is None:
        from ctfkit.cli import build_parser
        parser = build_parser()
    hints = _load_hints() if hints is None else hints

    sub = _sub_action(parser)
    helps = _helps(sub)
    result, seen = [], set()
    for name, child in sub.choices.items():
        if id(child) in seen:   # workspace / ws 처럼 별칭은 같은 파서를 가리킨다
            continue
        seen.add(id(child))
        hint = hints.get(name, {})
        if not hint.get("hidden"):
            result.append(_make_command(name, child, helps.get(name, ""), hint))
    result.sort(key=lambda c: (c.order, c.name))
    return result


def _check_type(f: Field, value: str) -> None:
    if f.value_type is None:
        return
    try:
        f.value_type(value)
    except ValueError:
        raise InputProblem(f"'{f.label}' 은(는) 숫자여야 합니다: {value}", f.dest) from None


def _option_args(f: Field, value) -> list:
    if f.kind == "check":
        return [f.option] if bool(value) != bool(f.arg_default) else []
    value = str(value).strip()
    if not value:
        if f.required:
            raise InputProblem(f"'{f.label}' 을(를) 입력하세요", f.dest)
        return []
    _check_type(f, value)
    if f.multiple:
        return [f"{f.option}={line.strip()}" for line in value.splitlines() if line.strip()]
    if f.arg_default is not None and value == str(f.arg_default):
        return []
    # --key=value 형태라야 '-' 로 시작하는 값도 옵션으로 오해받지 않는다
    return [f"{f.option}={value}"]


def _positional_args(f: Field, value) -> list:
    value = str(value).strip()
    if not value:
        if f.required:
            raise InputProblem(f"'{f.label}' 을(를) 입력하세요", f.dest)
        return []
    _check_type(f, value)
    if f.multiple:
        return [line.strip() for line in value.splitlines() if line.strip()]
    return [value]


def build_argv(command: Command, action: Action, values: dict) -> tuple:
    """화면 입력값을 (argv, stdin 문자열 또는 None) 으로 바꾼다."""
    argv = [command.name]
    for f in command.shared:
        if f.option:
            argv += _option_args(f, values.get(f.dest, f.default))
    if action.name:
        argv.append(action.name)

    stdin = None
    positionals = []
    for f in action.fields:
        value = values.get(f.dest, f.default)
        if f.stdin:
            # 파일을 고르면 파일이 우선이다 (console.read_input 과 같은 순서)
            has_file = any(o.dest == "file" and str(values.get("file", "")).strip() for o in action.fields)
            if has_file:
                continue
            if not str(value).strip():
                if any(o.dest == "file" for o in action.fields):
                    raise InputProblem(f"'{f.label}' 을(를) 채우거나 파일을 선택하세요", f.dest)
                raise InputProblem(f"'{f.label}' 을(를) 입력하세요", f.dest)
            stdin = str(value)
        elif f.option:
            argv += _option_args(f, value)
        else:
            positionals += _positional_args(f, value)

    if any(p.startswith("-") for p in positionals):
        argv.append("--")   # '-' 로 시작하는 값이 옵션으로 해석되지 않게
    return argv + positionals, stdin
