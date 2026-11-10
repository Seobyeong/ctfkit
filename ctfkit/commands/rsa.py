"""ctfkit rsa: 약한 RSA 설정에 대한 기초 공격 (표준 라이브러리만).

로컬 계산만 한다 — 주어진 공개 파라미터·암호문으로 소인수분해나 평문 복구를
시도할 뿐, 원격 서비스를 공격하지 않는다(학습 목적).

지원하는 공격:
- factor          : n 소인수분해 (페르마 / 폴라드 로 / 시험 나눗셈)
- decrypt         : n, e, c (+ 선택 p, q) 로 평문 복구
- wiener          : 작은 개인 지수 d 복구 (연분수)
- common-modulus  : 같은 n, 서로소 e 로 같은 평문을 두 번 암호화한 경우 평문 복구
"""

import sys

from ctfkit import rsautil
from ctfkit.console import is_quiet, log
from ctfkit.registry import TransformError

GUI_HINTS = {
    "rsa": {
        "label": "RSA",
        "order": 35,
        "group": "암호·인코딩",
        "desc": "약한 RSA 공격: 소인수분해 / 복호 / 비너 / 공통 모듈러스 (로컬 계산).",
        "actions": {
            "factor": "소인수분해",
            "decrypt": "복호",
            "wiener": "비너(작은 d)",
            "common-modulus": "공통 모듈러스",
        },
        "fields": {
            "n": {"label": "모듈러스 n"},
            "e": {"label": "공개 지수 e", "default": "65537"},
            "c": {"label": "암호문 c"},
            "p": {"label": "소인수 p (알면)"},
            "q": {"label": "소인수 q (알면)"},
            "e1": {"label": "e1"}, "c1": {"label": "c1"},
            "e2": {"label": "e2"}, "c2": {"label": "c2"},
        },
    },
}


def _int(text: str, what: str) -> int:
    """10진수 또는 0x/0o/0b 접두사 정수를 읽는다."""
    try:
        return int(str(text).strip(), 0)
    except (ValueError, TypeError) as e:
        raise TransformError(f"{what} 가 정수가 아닙니다: {text!r}") from e


def register(subparsers):
    parser = subparsers.add_parser("rsa", help="약한 RSA 공격 (분해·복호·비너·공통 모듈러스)")
    actions = parser.add_subparsers(dest="action", required=True, metavar="<action>")

    p_fac = actions.add_parser("factor", help="n 을 소인수분해한다")
    p_fac.add_argument("n", help="모듈러스 n (10진수 또는 0x..)")
    p_fac.set_defaults(func=_factor)

    p_dec = actions.add_parser("decrypt", help="n, e, c (+선택 p,q) 로 평문을 복구한다")
    p_dec.add_argument("-n", required=True, help="모듈러스 n")
    p_dec.add_argument("-e", default="65537", help="공개 지수 e (기본 65537)")
    p_dec.add_argument("-c", required=True, help="암호문 c")
    p_dec.add_argument("-p", help="소인수 p (알면 분해를 건너뛴다)")
    p_dec.add_argument("-q", help="소인수 q (알면 분해를 건너뛴다)")
    p_dec.set_defaults(func=_decrypt)

    p_wnr = actions.add_parser("wiener", help="작은 개인 지수 d 를 복구한다 (연분수)")
    p_wnr.add_argument("-n", required=True, help="모듈러스 n")
    p_wnr.add_argument("-e", required=True, help="공개 지수 e (크다)")
    p_wnr.add_argument("-c", help="암호문 c (주면 평문도 복구)")
    p_wnr.set_defaults(func=_wiener)

    p_cm = actions.add_parser("common-modulus", help="같은 n, 서로소 e 두 암호문에서 평문 복구")
    p_cm.add_argument("-n", required=True, help="모듈러스 n")
    p_cm.add_argument("--e1", required=True)
    p_cm.add_argument("--c1", required=True)
    p_cm.add_argument("--e2", required=True)
    p_cm.add_argument("--c2", required=True)
    p_cm.set_defaults(func=_common_modulus)


def _print_plaintext(m: int):
    """복구한 평문 정수를 정수·16진수·바이트(가능하면)로 보여 준다."""
    raw = rsautil.long_to_bytes(m)
    if is_quiet():
        # 답만: 글자로 읽히면 글자, 아니면 정수 하나
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        print(text if text and text.isprintable() else m)
        return
    print(f"m (int) = {m}")
    log(f"m (hex) = 0x{m:x}")
    try:
        text = raw.decode("utf-8")
        print(f"m (bytes) = {text}")
    except UnicodeDecodeError:
        print(f"m (bytes) = {raw!r}")


def _factor(args):
    n = _int(args.n, "n")
    if n < 2:
        raise TransformError("n 은 2 이상이어야 합니다")
    factors = rsautil.factorize(n)
    parts = []
    for p in sorted(factors):
        parts.append(f"{p}^{factors[p]}" if factors[p] > 1 else str(p))
    print(" * ".join(parts))
    if len(factors) == 1 and next(iter(factors.values())) == 1:
        log("[!] n 이 소수입니다 (RSA 모듈러스로는 부적절).")
    return 0


def _factors_to_pq(args):
    """p, q 가 주어지면 그대로, 아니면 n 을 분해해 소인수 목록을 돌려준다."""
    n = _int(args.n, "n")
    if args.p and args.q:
        p, q = _int(args.p, "p"), _int(args.q, "q")
        if p * q != n:
            raise TransformError("p * q 가 n 과 다릅니다")
        return n, {p: 1, q: 1}
    factors = rsautil.factorize(n)
    if len(factors) == 1 and next(iter(factors.values())) == 1:
        raise TransformError("n 이 소수라 복호할 수 없습니다")
    total = sum(factors.values())
    if total < 2:
        raise TransformError("n 을 분해하지 못했습니다 (소인수가 너무 커서; -p -q 로 직접 지정하세요)")
    return n, factors


def _decrypt(args):
    e = _int(args.e, "e")
    c = _int(args.c, "c")
    n, factors = _factors_to_pq(args)
    phi = rsautil.euler_phi(factors)
    try:
        d = rsautil.modinv(e, phi)
    except ValueError as exc:
        raise TransformError(f"d 를 구할 수 없습니다: e 와 phi 가 서로소가 아닙니다 ({exc})") from exc
    if not args.p or not args.q:
        log("[+] 분해 성공:", " * ".join(str(p) for p in sorted(factors)))
    _print_plaintext(pow(c, d, n))
    return 0


def _wiener(args):
    n = _int(args.n, "n")
    e = _int(args.e, "e")
    d = rsautil.wiener(e, n)
    if d is None:
        raise TransformError("비너 공격 실패 (d 가 충분히 작지 않습니다)")
    log(f"d = {d}")
    if args.c:
        _print_plaintext(pow(_int(args.c, "c"), d, n))
    else:
        print(d if is_quiet() else f"d = {d}")
    return 0


def _common_modulus(args):
    n = _int(args.n, "n")
    try:
        m = rsautil.common_modulus(
            _int(args.e1, "e1"), _int(args.c1, "c1"),
            _int(args.e2, "e2"), _int(args.c2, "c2"), n,
        )
    except ValueError as exc:
        raise TransformError(str(exc)) from exc
    _print_plaintext(m)
    return 0
