"""ctfkit workspace: 문제별 작업 폴더 / 실행한 명령 기록 / 풀이 노트.

한 CTF 문제를 풀 때 폴더 하나에 노트·다운로드 파일·명령 기록을 모아 둔다.
외부 의존성 없음. 작업 폴더는 기본적으로 현재 디렉터리 아래에 만든다 (--root 로 변경).
"""

import datetime
import os

from ctfkit.registry import TransformError

# 작업 폴더임을 표시하는 숨김 파일. list 가 이 파일로 작업 폴더를 찾는다.
_MARKER = ".ctfkit-workspace"
_NOTES = "notes.md"
_LOG = "commands.log"

GUI_HINTS = {
    "workspace": {
        "label": "작업 폴더",
        "order": 70,
        "desc": "문제별 폴더, 명령 기록, 풀이 노트를 관리합니다.",
        "actions": {"list": "목록", "new": "새로 만들기", "info": "정보", "log": "명령 기록"},
        "fields": {
            # 더블클릭 등으로 실행하면 현재 폴더를 예측하기 어려우니 실제 경로를 보여 준다
            "root": {"label": "상위 폴더", "default": os.getcwd},
            "name": {"label": "문제 이름"},
            "command": {"label": "기록할 명령", "kind": "entry"},
        },
    },
}

_NOTE_TEMPLATE = """# {name}

- 분야:
- 출처/링크:
- 생성: {now}

## 관찰 (주어진 것)

## 시도

## 풀이 / 플래그

"""


def _root(args) -> str:
    return getattr(args, "root", None) or os.getcwd()


def _path(args, name: str) -> str:
    return os.path.join(_root(args), name)


def _require(args, name: str) -> str:
    path = _path(args, name)
    if not os.path.isfile(os.path.join(path, _MARKER)):
        raise TransformError(f"작업 폴더가 아닙니다: {name} (ctfkit workspace new {name} 로 먼저 생성)")
    return path


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def register(subparsers):
    parser = subparsers.add_parser("workspace", aliases=["ws"], help="문제별 작업 폴더 관리")
    parser.add_argument("--root", help="작업 폴더들을 담을 상위 경로 (기본: 현재 디렉터리)")
    actions = parser.add_subparsers(dest="action", required=True, metavar="<action>")

    p_new = actions.add_parser("new", help="작업 폴더와 노트 템플릿 생성")
    p_new.add_argument("name", help="문제 이름 (폴더 이름)")
    p_new.set_defaults(func=_new)

    actions.add_parser("list", help="작업 폴더 목록").set_defaults(func=_list)

    p_log = actions.add_parser("log", help="실행한 명령을 기록에 추가")
    p_log.add_argument("name", help="문제 이름")
    p_log.add_argument("command", nargs="+", help="기록할 명령 (그대로 저장)")
    p_log.set_defaults(func=_log)

    p_info = actions.add_parser("info", help="작업 폴더 요약 (노트 경로·명령 기록 수)")
    p_info.add_argument("name", help="문제 이름")
    p_info.set_defaults(func=_info)


def _new(args):
    path = _path(args, args.name)
    marker = os.path.join(path, _MARKER)
    if os.path.isfile(marker):
        raise TransformError(f"이미 있는 작업 폴더입니다: {args.name}")
    os.makedirs(path, exist_ok=True)
    open(marker, "w").close()
    notes = os.path.join(path, _NOTES)
    if not os.path.exists(notes):
        with open(notes, "w", encoding="utf-8") as f:
            f.write(_NOTE_TEMPLATE.format(name=args.name, now=_now()))
    open(os.path.join(path, _LOG), "a", encoding="utf-8").close()
    print(f"[+] 작업 폴더 생성: {path}")
    print(f"    노트: {os.path.join(path, _NOTES)}")
    return 0


def _list(args):
    root = _root(args)
    try:
        entries = sorted(os.listdir(root))
    except OSError as e:
        raise TransformError(f"폴더를 읽을 수 없습니다: {e}") from e
    found = [e for e in entries if os.path.isfile(os.path.join(root, e, _MARKER))]
    if not found:
        print(f"작업 폴더가 없습니다 ({root}). ctfkit workspace new <이름> 으로 만드세요.")
        return 1
    for name in found:
        log = os.path.join(root, name, _LOG)
        count = _line_count(log)
        print(f"  {name:<24} 명령 {count}개")
    return 0


def _line_count(path: str) -> int:
    try:
        with open(path, encoding="utf-8") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def _log(args):
    path = _require(args, args.name)
    line = f"[{_now()}] {' '.join(args.command)}\n"
    with open(os.path.join(path, _LOG), "a", encoding="utf-8") as f:
        f.write(line)
    print(f"[+] 기록함: {line.strip()}")
    return 0


def _info(args):
    path = _require(args, args.name)
    print(f"작업 폴더: {path}")
    print(f"노트:     {os.path.join(path, _NOTES)}")
    print(f"명령 기록: {_line_count(os.path.join(path, _LOG))}개 ({os.path.join(path, _LOG)})")
    others = sorted(
        e for e in os.listdir(path)
        if e not in (_MARKER, _NOTES, _LOG)
    )
    if others:
        print(f"파일:     {', '.join(others)}")
    return 0
