"""ctfkit base: 진법(2/8/10/16) 변환. 표준 라이브러리만 사용한다.

입력 진법은 접두사(0x/0o/0b)로 자동 인식하거나 --from 으로 지정한다. 출력은 특정
진법(--to)만 보거나, 생략하면 2·8·10·16 진수를 한 번에 보여준다.
"""

from ctfkit.registry import TransformError

GUI_HINTS = {
    "base": {
        "label": "진법 변환",
        "order": 22,
        "group": "암호·인코딩",
        "desc": "2/8/10/16 진수 상호 변환 (0x/0o/0b 접두사 자동 인식).",
        "actions": {},  # 하위 action 없이 바로 값을 받는 단일 명령
        "fields": {
            "value": {"label": "값 (예: 255, 0xff, 0b1010)"},
            "from_base": {"label": "입력 진법 (비우면 접두사로 인식)", "default": ""},
            "to": {"label": "출력 진법 (비우면 전부)", "suggest": ["2", "8", "10", "16"], "default": ""},
        },
    },
}

_FORMAT = {2: ("2진수 ", "b"), 8: ("8진수 ", "o"), 10: ("10진수", "d"), 16: ("16진수", "x")}


def register(subparsers):
    p = subparsers.add_parser("base", help="진법(2/8/10/16) 변환")
    p.add_argument("value", help="변환할 값 (0x/0o/0b 접두사 인식, 아니면 10진수)")
    p.add_argument("--from", type=int, dest="from_base", metavar="N",
                   help="입력 진법 2~36 (생략하면 접두사로 자동 인식)")
    p.add_argument("--to", type=int, metavar="N", help="출력 진법 2/8/10/16 (생략하면 전부)")
    p.set_defaults(func=_run)


def _parse(value: str, from_base: int | None) -> int:
    value = value.strip()
    try:
        if from_base is None:
            # 0x/0o/0b 접두사가 있으면 그에 맞게, 없으면 10진수로 해석
            return int(value, 0)
        if not 2 <= from_base <= 36:
            raise TransformError("--from 은 2~36 이어야 합니다")
        return int(value, from_base)
    except ValueError as e:
        raise TransformError(f"'{value}' 를 해석할 수 없습니다: {e}") from e


def _run(args):
    num = _parse(args.value, args.from_base)
    neg = num < 0
    mag = abs(num)
    sign = "-" if neg else ""

    if args.to is not None:
        if args.to not in _FORMAT:
            raise TransformError("--to 는 2, 8, 10, 16 중 하나여야 합니다")
        print(sign + format(mag, _FORMAT[args.to][1]))
        return 0

    for b in (2, 8, 10, 16):
        label, spec = _FORMAT[b]
        print(f"{label}: {sign}{format(mag, spec)}")
    return 0
