"""ctfkit config: 대회별 설정 (플래그 형식, 허용 호스트).

드림핵이 아닌 대회에서는 플래그 형식(picoCTF{...})과 문제 서버 주소가 다르다. 매번 --flag, --allow 를 주는 대신
대회 폴더에 `.ctfkit.json` 하나를 두면 그 아래에서 실행하는 모든 명령이 따른다. 읽는 규칙은 ctfkit/settings.py.

  config show                      지금 적용되는 설정과 그 파일
  config set flag 'picoCTF\\{.*?\\}'  플래그 정규식
  config add allow .ctf.example.com 허용 호스트 추가 ('.' 로 시작하면 하위 도메인 전체)
  config remove allow HOST          허용 호스트 빼기
  config unset flag|allow           항목 지우기 (기본값으로)
"""

import os

from ctfkit import settings
from ctfkit.console import log
from ctfkit.flags import DEFAULT_FLAG_PATTERN
from ctfkit.registry import TransformError

GUI_HINTS = {
    "config": {
        "label": "대회 설정",
        "order": 75,
        "group": "작업",
        "desc": "대회 폴더의 플래그 형식과 허용 호스트를 정합니다 (.ctfkit.json).",
        "actions": {"show": "보기", "set": "값 정하기", "add": "허용 호스트 추가",
                    "remove": "허용 호스트 빼기", "unset": "지우기"},
        "fields": {
            "key": {"label": "항목"},
            "value": {"label": "값"},
            "host": {"label": "호스트 (예: .ctf.example.com)"},
            "dir": {"label": "대회 폴더 (비우면 현재 폴더)", "kind": "dir"},
        },
    },
}


def register(subparsers):
    parser = subparsers.add_parser("config", help="대회별 설정: 플래그 형식·허용 호스트 (.ctfkit.json)")
    actions = parser.add_subparsers(dest="action", required=True, metavar="<action>")

    def _dir(p):
        p.add_argument("--dir", help="이 폴더 기준으로 설정을 찾고 쓴다 (기본: 현재 폴더)")

    p = actions.add_parser("show", help="지금 적용되는 설정")
    _dir(p)
    p.set_defaults(func=_show)

    p = actions.add_parser("set", help="값 정하기 (flag: 정규식, allow: 쉼표로 구분한 호스트 목록)")
    p.add_argument("key", choices=settings.KEYS)
    p.add_argument("value")
    _dir(p)
    p.set_defaults(func=_set)

    p = actions.add_parser("add", help="허용 호스트 추가")
    p.add_argument("key", choices=["allow"])
    p.add_argument("host")
    _dir(p)
    p.set_defaults(func=_add)

    p = actions.add_parser("remove", help="허용 호스트 빼기")
    p.add_argument("key", choices=["allow"])
    p.add_argument("host")
    _dir(p)
    p.set_defaults(func=_remove)

    p = actions.add_parser("unset", help="항목 지우기 (기본값으로 돌아감)")
    p.add_argument("key", choices=settings.KEYS)
    _dir(p)
    p.set_defaults(func=_unset)


def _base(args) -> str:
    folder = args.dir or os.getcwd()
    if not os.path.isdir(folder):
        raise TransformError(f"폴더가 아닙니다: {folder}")
    return folder


def _show(args):
    return _report(_base(args))


def _report(folder: str) -> int:
    path, ignored = settings.find(folder)
    current = settings.load_file(path) if path else settings.Settings()
    env = os.environ.get("CTFKIT_CONFIG", "").strip()
    if env:
        log(f"[i] 환경 변수 CTFKIT_CONFIG={env} 가 있어 실제 명령은 이 값을 따릅니다.")
    print(f"설정 파일: {path or '(없음: 기본값)'}")
    print(f"flag:  {current.flag or DEFAULT_FLAG_PATTERN + '  (기본)'}")
    print("allow: localhost, *.dreamhack.games (기본)" + "".join(f", {h}" for h in current.allow))
    for item in ignored:
        log(f"[!] 작업 폴더 안의 설정 파일은 쓰지 않습니다 (문제 파일일 수 있음): {item}")
    return 0


def _update(args, change) -> int:
    path = settings.write_target(_base(args))
    data = settings.read_raw(path)
    change(data)
    settings.save(path, data)
    log(f"[+] 저장: {path}")
    return _report(os.path.dirname(path))


def _set(args):
    def change(data):
        if args.key == "flag":
            data["flag"] = settings.check_flag(args.value)
        else:
            data["allow"] = list(dict.fromkeys(settings.check_host(h) for h in args.value.split(",") if h.strip()))
    return _update(args, change)


def _add(args):
    host = settings.check_host(args.host)

    def change(data):
        data["allow"] = list(dict.fromkeys([*(data.get("allow") or []), host]))
    return _update(args, change)


def _remove(args):
    host = args.host.strip().lower()

    def change(data):
        allow = data.get("allow") or []
        if host not in allow:
            raise TransformError(f"허용 호스트 목록에 없습니다: {host}")
        data["allow"] = [h for h in allow if h != host]
    return _update(args, change)


def _unset(args):
    def change(data):
        data.pop(args.key, None)
    return _update(args, change)
