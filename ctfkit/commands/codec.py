"""ctfkit codec list / decode / encode"""

from ctfkit import registry
from ctfkit.console import read_input, write_output
from ctfkit.registry import TransformError


def register(subparsers):
    parser = subparsers.add_parser("codec", help="인코딩/디코딩")
    actions = parser.add_subparsers(dest="action", required=True, metavar="<action>")

    actions.add_parser("list", help="사용 가능한 변환 목록").set_defaults(func=_list)

    for action in ("decode", "encode"):
        p = actions.add_parser(action, help=f"{action} 수행")
        p.add_argument("transform", help="변환 이름 (codec list 로 확인)")
        p.add_argument("data", nargs="?", default="-", help="입력 문자열 (생략하거나 '-' 면 stdin)")
        p.add_argument("-f", "--file", help="파일에서 입력 읽기")
        p.add_argument("-k", "--key", help="키가 필요한 변환에 쓸 키")
        p.set_defaults(func=_run)


def _list(args):
    for t in registry.all_transforms():
        names = ", ".join((t.name, *t.aliases))
        key_mark = " [key]" if t.needs_key else ""
        print(f"{names:<20} {t.description}{key_mark}")
    return 0


def _run(args):
    t = registry.get(args.transform)
    if t.needs_key and args.key is None:
        raise TransformError(f"{t.name} 은(는) --key 가 필요합니다 (예: --key {t.example_key})")

    data = read_input(args.data, args.file)
    if args.action == "decode":
        result = t.decode(data, args.key)
    else:
        result = t.encode(data, args.key)
    write_output(result)
    return 0
