"""ctfkit crack: 키가 필요한 변환의 키를 키 없이 추정한다."""

from ctfkit import registry
from ctfkit.analysis import text_score
from ctfkit.console import preview, read_input
from ctfkit.flags import compile_flag_pattern, find_flag
from ctfkit.registry import TransformError


def register(subparsers):
    p = subparsers.add_parser("crack", help="키 없이 키를 추정해 해독 (caesar, vigenere, xor)")
    p.add_argument("transform", help="변환 이름 (codec list 에서 [key] 표시된 것)")
    p.add_argument("data", nargs="?", default="-", help="입력 문자열 (생략하거나 '-' 면 stdin)")
    p.add_argument("-f", "--file", help="파일에서 입력 읽기")
    p.add_argument("-n", "--top", type=int, default=5, help="보여줄 키 후보 수 (기본 5)")
    p.set_defaults(func=_run)


def _run(args):
    t = registry.get(args.transform)
    if not t.needs_key:
        raise TransformError(f"{t.name} 은(는) 키가 없는 변환입니다. codec decode 를 사용하세요")

    data = read_input(args.data, args.file)
    keys = t.guess_keys(data, limit=args.top)
    if not keys:
        raise TransformError(f"{t.name}: 키를 추정할 수 없습니다 (입력이 너무 짧거나 형식이 맞지 않음)")

    pattern = compile_flag_pattern()
    rows = []
    for key in keys:
        plain = t.decode(data, key)
        rows.append((key, text_score(plain), find_flag(plain, pattern), plain))

    print(f"{'key':<18} {'score':>5}  result")
    for key, score, flag, plain in rows:
        mark = "  <- flag" if flag else ""
        print(f"{key:<18} {score:5.2f}  {preview(plain)}{mark}")
    return 0
