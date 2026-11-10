"""ctfkit jwt: JWT 디코드 / 변조(forge) / HS256 시크릿 사전 공격.

표준 라이브러리(base64, json, hmac, hashlib)만 사용한다. 외부 의존성 없음.

JWT 는 `header.payload.signature` 세 조각을 '.' 로 이은 문자열이며, 각 조각은
base64url(패딩 '=' 없음) 로 인코딩돼 있다. header·payload 는 JSON 이다.
서명은 `base64url(header).base64url(payload)` (= signing input) 에 대해 계산한다.
"""

import base64
import hashlib
import hmac
import json
import sys

from ctfkit.console import is_quiet, log, parse_key, read_input
from ctfkit.registry import TransformError

# HS 계열(대칭키 HMAC) 알고리즘만 서명/검증/크랙을 지원한다.
# RS/ES(비대칭) 는 개인키가 필요해 CTF 입문 범위 밖이라 뺐다.
_HS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

GUI_HINTS = {
    "jwt": {
        "label": "JWT",
        "order": 65,
        "desc": "JWT 디코드, 변조(alg:none/서명), HS256 시크릿 사전 공격.",
        "actions": {"decode": "디코드", "forge": "변조", "crack": "시크릿 크랙"},
        "fields": {
            "token": {"label": "토큰"},
            "verify": {"label": "서명 검증용 시크릿"},
            "alg": {"label": "알고리즘", "suggest": ["none", *_HS], "default": "none"},
            "set": {"label": "페이로드 수정 (key=value, 여러 번)"},
            "secret": {"label": "서명 시크릿 (HS 계열)"},
            "words": {"label": "워드리스트"},
        },
    },
}


def _b64url_decode(part: str) -> bytes:
    """base64url 조각을 디코드한다. 생략된 '=' 패딩을 다시 채워 준다."""
    pad = -len(part) % 4
    try:
        return base64.urlsafe_b64decode(part + "=" * pad)
    except (ValueError, TypeError) as e:
        raise TransformError(f"base64url 디코드 실패: {part!r} ({e})") from e


def _b64url_encode(raw: bytes) -> str:
    """base64url 로 인코딩하고 '=' 패딩을 떼어 낸다 (JWT 규격)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _split(token: str) -> tuple[str, str, str]:
    """토큰을 세 조각으로 나눈다. signature 가 없으면 빈 문자열."""
    token = token.strip()
    parts = token.split(".")
    if len(parts) == 2:
        parts.append("")
    if len(parts) != 3:
        raise TransformError(
            f"JWT 형식이 아닙니다 ('.' 로 나뉜 2~3 조각이어야 함, 받은 조각 수: {len(parts)})"
        )
    return parts[0], parts[1], parts[2]


def _decode_json(part: str, what: str) -> dict:
    raw = _b64url_decode(part)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as e:
        raise TransformError(f"{what} 가 올바른 JSON 이 아닙니다: {e}") from e
    if not isinstance(value, dict):
        raise TransformError(f"{what} 는 JSON 객체여야 합니다 (받은 타입: {type(value).__name__})")
    return value


def _sign(alg: str, signing_input: bytes, secret: bytes) -> str:
    """HS 계열 서명을 계산해 base64url 로 돌려준다."""
    func = _HS.get(alg.upper())
    if func is None:
        raise TransformError(
            f"서명을 지원하지 않는 알고리즘입니다: {alg} (지원: none, {', '.join(_HS)})"
        )
    mac = hmac.new(secret, signing_input, func).digest()
    return _b64url_encode(mac)


def _dumps(obj: dict) -> str:
    """JWT 구현들이 쓰는 방식대로 공백 없이 JSON 직렬화한다."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def register(subparsers):
    parser = subparsers.add_parser("jwt", help="JWT 디코드·변조·HS256 시크릿 공격")
    actions = parser.add_subparsers(dest="action", required=True, metavar="<action>")

    p_dec = actions.add_parser("decode", help="헤더·페이로드 디코드 (서명 검증은 선택)")
    p_dec.add_argument("token", nargs="?", default="-", help="JWT 문자열 (생략/'-' 면 stdin)")
    p_dec.add_argument(
        "--verify", metavar="SECRET",
        help="HS 계열 서명을 이 시크릿으로 검증 ('0x' 접두사면 16진수)",
    )
    p_dec.set_defaults(func=_decode)

    p_forge = actions.add_parser("forge", help="토큰을 변조해 다시 만든다 (alg:none 또는 재서명)")
    p_forge.add_argument("token", nargs="?", help="기준 토큰 (생략하면 빈 페이로드부터 시작)")
    p_forge.add_argument(
        "--alg", default="none",
        help="새 alg 값 (none = 서명 제거, HS256/384/512 = --secret 로 재서명)",
    )
    p_forge.add_argument(
        "--set", action="append", default=[], metavar="KEY=VALUE", dest="set",
        help="페이로드 클레임 설정/추가 (여러 번 가능, 값은 JSON 으로 해석 후 실패하면 문자열)",
    )
    p_forge.add_argument(
        "--secret", help="HS 계열 재서명에 쓸 시크릿 ('0x' 접두사면 16진수)",
    )
    p_forge.set_defaults(func=_forge)

    p_crack = actions.add_parser("crack", help="워드리스트로 HS256 서명 시크릿을 찾는다")
    p_crack.add_argument("token", nargs="?", default="-", help="HS 계열로 서명된 JWT (생략/'-' 면 stdin)")
    p_crack.add_argument("-w", "--words", required=True, help="워드리스트 파일 경로 (한 줄에 하나)")
    p_crack.set_defaults(func=_crack)


def _read_token(arg: str) -> str:
    """토큰 인자를 읽는다. '-' 또는 생략이면 stdin 에서(다른 명령과 동일한 입력 규칙)."""
    return read_input(arg, None).decode("utf-8", "replace").strip()


def _parse_set(pairs: list[str]) -> dict:
    """--set KEY=VALUE 목록을 dict 로. 값은 JSON 으로 먼저 해석(true/42/"x") 하고, 실패하면 문자열."""
    out: dict = {}
    for item in pairs:
        if "=" not in item:
            raise TransformError(f"--set 은 KEY=VALUE 형식이어야 합니다: {item!r}")
        key, _, value = item.partition("=")
        try:
            out[key] = json.loads(value)
        except json.JSONDecodeError:
            out[key] = value
    return out


def _decode(args):
    header_b64, payload_b64, sig_b64 = _split(_read_token(args.token))
    header = _decode_json(header_b64, "헤더")
    payload = _decode_json(payload_b64, "페이로드")

    if is_quiet():
        # 답만: 헤더 한 줄, 페이로드 한 줄 (들여쓰기 없는 JSON)
        print(json.dumps(header, separators=(",", ":"), ensure_ascii=False))
        print(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))
    else:
        print("[헤더]")
        print(json.dumps(header, indent=2, ensure_ascii=False))
        print("\n[페이로드]")
        print(json.dumps(payload, indent=2, ensure_ascii=False))

    alg = str(header.get("alg", ""))
    log(f"\n[alg] {alg or '(없음)'}")
    if alg.lower() == "none":
        log("[!] alg=none: 서명이 없는 토큰입니다 (서명 미검증 서버면 변조 가능).")

    if args.verify is not None:
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected = _sign(alg, signing_input, parse_key(args.verify))
        if hmac.compare_digest(expected, sig_b64):
            log("[서명] 유효함 (시크릿 일치)")
        else:
            log("[서명] 불일치 (시크릿이 틀렸거나 변조된 토큰)")
            return 1
    return 0


def _forge(args):
    if args.token:
        header_b64, payload_b64, _ = _split(args.token)
        header = _decode_json(header_b64, "헤더")
        payload = _decode_json(payload_b64, "페이로드")
    else:
        header = {"typ": "JWT"}
        payload = {}

    payload.update(_parse_set(args.set))
    header["alg"] = args.alg

    header_b64 = _b64url_encode(_dumps(header).encode("utf-8"))
    payload_b64 = _b64url_encode(_dumps(payload).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    if args.alg.lower() == "none":
        if args.secret is not None:
            raise TransformError("alg=none 에는 --secret 을 쓸 수 없습니다 (서명이 없는 알고리즘)")
        signature = ""
    else:
        if args.secret is None:
            raise TransformError(f"alg={args.alg} 는 재서명이 필요합니다. --secret 을 지정하세요")
        signature = _sign(args.alg, signing_input, parse_key(args.secret))

    print(f"{header_b64}.{payload_b64}.{signature}")
    return 0


def _crack(args):
    header_b64, payload_b64, sig_b64 = _split(_read_token(args.token))
    header = _decode_json(header_b64, "헤더")
    alg = str(header.get("alg", "")).upper()
    if alg not in _HS:
        raise TransformError(
            f"HS 계열 토큰이 아닙니다 (alg={header.get('alg')!r}). 크랙은 HS256/384/512 만 지원합니다"
        )

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    tried = 0
    try:
        with open(args.words, "rb") as f:
            for raw in f:
                word = raw.rstrip(b"\r\n")
                tried += 1
                if hmac.compare_digest(_sign(alg, signing_input, word), sig_b64):
                    found = word.decode("utf-8", "replace")
                    print(found if is_quiet() else f"[+] 찾음: {found}  ({alg}, {tried}개 시도)")
                    return 0
    except OSError as e:
        raise TransformError(f"워드리스트를 읽을 수 없습니다: {e}") from e

    log(f"[-] 찾지 못함 ({tried}개 단어, {alg})")
    return 1
