"""ctfkit web: 워게임 서버 대상 HTTP 요청 / curl 재현 / 파라미터 퍼징.

안전장치 (README의 윤리 규정을 코드로 강제):
  - allowlist 밖 호스트로는 절대 요청하지 않는다 (기본: localhost, *.dreamhack.games).
  - 반복 요청에는 요청 간 최소 간격(--delay)과 총량 상한(--max)을 둔다.
표준 라이브러리(urllib, http.cookiejar)만 사용한다.
"""

import base64
import binascii
import os
import re
import shlex
import string
import sys
import time
import urllib.error
import urllib.request
from http.cookiejar import LWPCookieJar
from urllib.parse import quote, urlparse

# 기본 허용 호스트: 본인이 띄운 실습 서버와 드림핵 워게임 인스턴스만.
_DEFAULT_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
# 접미사로 허용하는 도메인 (하위 도메인 포함). 드림핵 워게임 인스턴스는 *.dreamhack.games.
_DEFAULT_SUFFIXES = {".dreamhack.games"}

# 반복(fuzz/repeat) 기본값
_DEFAULT_DELAY = 0.5     # 요청 사이 최소 간격(초)
_DEFAULT_MAX = 200       # 총 요청 수 상한
_FUZZ_MARKER = "FUZZ"

GUI_HINTS = {
    "web": {
        "label": "웹 요청",
        "order": 60,
        "desc": "allowlist 호스트에만 요청합니다 (기본: localhost, *.dreamhack.games).",
        "actions": {"send": "요청", "curl": "curl 재현", "fuzz": "퍼징",
                    "oracle": "오라클 복구", "padding-oracle": "패딩 오라클", "diff": "응답 비교"},
        "fields": {
            "url": {"label": "URL"},
            "url1": {"label": "기준 URL"},
            "url2": {"label": "비교할 URL"},
            "max_lines": {"label": "본문 diff 최대 줄"},
            "fuzz.url": {"label": f"URL ({_FUZZ_MARKER} 위치 표시)"},
            "oracle.url": {"label": f"URL ({_FUZZ_MARKER} 위치 표시)"},
            "padding-oracle.url": {"label": f"URL ({_FUZZ_MARKER} 위치 표시)"},
            "cipher": {"label": "암호문(base64)"},
            "bad": {"label": "패딩 틀림 패턴(정규식)"},
            "ok": {"label": "패딩 맞음 패턴(정규식)"},
            "block": {"label": "블록 크기"},
            "iv": {"label": "IV(hex)"},
            "raw": {"label": "base64 URL 인코딩 안 함"},
            "command": {"label": "curl 명령", "kind": "text"},
            "method": {"label": "메서드", "suggest": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]},
            "header": {"label": "헤더 (한 줄에 하나)"},
            "data": {"label": "본문"},
            "allow": {"label": "허용 호스트 추가", "kind": "entry"},
            "cookies": {"label": "쿠키 파일"},
            "words": {"label": "워드리스트"},
            "hide": {"label": "숨길 상태코드"},
            "match": {"label": "표시 패턴(정규식)"},
            "fail": {"label": "실패 패턴(정규식)"},
            "success": {"label": "성공 패턴(정규식)"},
            "charset": {"label": "문자셋"},
            "max_length": {"label": "최대 길이"},
            "timeout": {"label": "타임아웃(초)"},
            "delay": {"label": "요청 간격(초)"},
            "max": {"label": "최대 요청 수"},
            "show_headers": {"label": "응답 상태 표시"},
        },
    },
}


def allowed_hosts() -> tuple[set[str], set[str]]:
    """허용 호스트 집합과 접미사 집합. 환경변수 CTFKIT_ALLOW 로 추가할 수 있다 (쉼표 구분)."""
    hosts = set(_DEFAULT_HOSTS)
    suffixes = set(_DEFAULT_SUFFIXES)
    extra = os.environ.get("CTFKIT_ALLOW", "")
    for item in extra.split(","):
        item = item.strip().lower()
        if not item:
            continue
        (suffixes if item.startswith(".") else hosts).add(item)
    return hosts, suffixes


def is_allowed(url: str, extra: list[str] | None = None) -> bool:
    """url 의 호스트가 allowlist 안에 있는지 검사한다."""
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    hosts, suffixes = allowed_hosts()
    for item in extra or []:
        item = item.strip().lower()
        (suffixes if item.startswith(".") else hosts).add(item)
    if host in hosts:
        return True
    return any(host.endswith(sfx) for sfx in suffixes)


def _ensure_allowed(url: str, extra: list[str] | None) -> None:
    if not is_allowed(url, extra):
        host = urlparse(url).hostname or "?"
        raise ValueError(
            f"허용되지 않은 호스트입니다: {host}\n"
            f"ctfkit web 은 localhost 와 *.dreamhack.games 에만 요청합니다. "
            f"다른 실습 서버는 --allow 로 명시하거나 환경변수 CTFKIT_ALLOW 에 추가하세요."
        )


def parse_curl(command: str) -> dict:
    """curl 명령 문자열을 파싱해 {method, url, headers, data} 로 돌려준다.

    지원: -X/--request, -H/--header, -d/--data/--data-raw, -b/--cookie, -A/--user-agent.
    """
    tokens = shlex.split(command)
    if tokens and tokens[0] == "curl":
        tokens = tokens[1:]

    method = None
    url = None
    headers = {}
    data = None
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-X", "--request"):
            i += 1
            method = tokens[i]
        elif tok in ("-H", "--header"):
            i += 1
            k, _, v = tokens[i].partition(":")
            headers[k.strip()] = v.strip()
        elif tok in ("-d", "--data", "--data-raw", "--data-binary"):
            i += 1
            data = tokens[i]
        elif tok in ("-b", "--cookie"):
            i += 1
            headers["Cookie"] = tokens[i]
        elif tok in ("-A", "--user-agent"):
            i += 1
            headers["User-Agent"] = tokens[i]
        elif tok in ("-e", "--referer"):
            i += 1
            headers["Referer"] = tokens[i]
        elif tok in ("-I", "--head"):
            method = "HEAD"
        elif tok in ("-G", "--get"):
            method = "GET"
        elif tok.startswith("-"):
            pass   # 모르는 플래그(-s, -k, -L 등)는 무시
        elif url is None:
            url = tok
        i += 1

    if url is None:
        raise ValueError("curl 명령에서 URL 을 찾지 못했습니다")
    if method is None:
        method = "POST" if data is not None else "GET"
    return {"method": method, "url": url, "headers": headers, "data": data}


def _do_request(url, method, headers, data, cookiejar, timeout):
    """요청 하나를 보내고 (상태코드, 본문bytes) 를 돌려준다. allowlist 는 호출 전에 검사한다."""
    body = data.encode("utf-8") if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, method=method.upper())
    for k, v in headers.items():
        req.add_header(k, v)

    handlers = []
    if cookiejar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(cookiejar))
    opener = urllib.request.build_opener(*handlers)
    try:
        resp = opener.open(req, timeout=timeout)
        return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        # 4xx/5xx 도 CTF 에서는 유의미한 응답이므로 본문을 함께 돌려준다
        return e.code, e.read()


def register(subparsers):
    parser = subparsers.add_parser("web", help="HTTP 요청·curl 재현·퍼징 (allowlist 전용)")
    actions = parser.add_subparsers(dest="action", required=True, metavar="<action>")

    for name, help_text in (("send", "단일 HTTP 요청"), ("curl", "curl 명령 재현")):
        p = actions.add_parser(name, help=help_text)
        if name == "send":
            p.add_argument("url", help="요청 URL")
            p.add_argument("-X", "--method", default="GET", help="HTTP 메서드 (기본 GET)")
            p.add_argument("-H", "--header", action="append", default=[],
                           metavar="'K: V'", help="헤더 (여러 번 지정 가능)")
            p.add_argument("-d", "--data", help="요청 본문")
        else:
            p.add_argument("command", help="curl 명령 문자열 (따옴표로 감싸기)")
        p.add_argument("--allow", action="append", default=[], metavar="HOST",
                       help="allowlist 에 호스트 추가 ('.' 로 시작하면 접미사)")
        p.add_argument("--cookies", metavar="FILE", help="쿠키 파일 (있으면 불러오고, 끝나면 저장)")
        p.add_argument("--timeout", type=float, default=10.0, help="타임아웃 초 (기본 10)")
        p.add_argument("--show-headers", action="store_true", help="응답 상태·헤더도 출력")
        p.set_defaults(func=_send if name == "send" else _curl)

    p_fuzz = actions.add_parser("fuzz", help=f"워드리스트로 '{_FUZZ_MARKER}' 자리를 치환하며 반복 요청")
    p_fuzz.add_argument("url", help=f"URL. '{_FUZZ_MARKER}' 가 치환 지점 (예: ?id={_FUZZ_MARKER})")
    p_fuzz.add_argument("-w", "--words", required=True, help="워드리스트 파일")
    p_fuzz.add_argument("-X", "--method", default="GET", help="HTTP 메서드 (기본 GET)")
    p_fuzz.add_argument("-H", "--header", action="append", default=[], metavar="'K: V'")
    p_fuzz.add_argument("-d", "--data", help=f"요청 본문 (여기에도 '{_FUZZ_MARKER}' 사용 가능)")
    p_fuzz.add_argument("--allow", action="append", default=[], metavar="HOST")
    p_fuzz.add_argument("--delay", type=float, default=_DEFAULT_DELAY,
                        help=f"요청 사이 최소 간격 초 (기본 {_DEFAULT_DELAY})")
    p_fuzz.add_argument("--max", type=int, default=_DEFAULT_MAX,
                        help=f"총 요청 수 상한 (기본 {_DEFAULT_MAX})")
    p_fuzz.add_argument("--timeout", type=float, default=10.0, help="타임아웃 초 (기본 10)")
    p_fuzz.add_argument("--hide", metavar="CODE", help="이 상태코드들은 숨김 (쉼표 구분, 예: 404,403)")
    p_fuzz.add_argument("--match", metavar="REGEX", help="응답 본문이 이 정규식과 일치하는 요청만 표시")
    p_fuzz.add_argument("--fail", metavar="REGEX", help="응답 본문이 이 정규식과 일치하면 숨김")
    p_fuzz.set_defaults(func=_fuzz)

    p_oracle = actions.add_parser(
        "oracle",
        help=f"접두사 비교 취약점을 한 글자씩 자동 복구 ('{_FUZZ_MARKER}' 자리를 늘려가며 시도)",
    )
    p_oracle.add_argument("url", help=f"URL. '{_FUZZ_MARKER}' 가 치환 지점")
    p_oracle.add_argument("-X", "--method", default="POST", help="HTTP 메서드 (기본 POST)")
    p_oracle.add_argument("-H", "--header", action="append", default=[], metavar="'K: V'")
    p_oracle.add_argument("-d", "--data", help=f"요청 본문 (여기에도 '{_FUZZ_MARKER}' 사용 가능)")
    p_oracle.add_argument("--charset", default=string.ascii_lowercase + string.digits,
                          help="한 자리에 시도할 문자들 (기본: 소문자 a-z + 숫자 0-9)")
    p_oracle.add_argument("--max-length", type=int, default=32, dest="max_length",
                          help="복구할 최대 길이 (기본 32)")
    p_oracle.add_argument("--success", metavar="REGEX",
                          help="응답 본문에 이 정규식이 있으면 그 글자를 정답으로 채택")
    p_oracle.add_argument("--fail", metavar="REGEX",
                          help="응답 본문에 이 정규식이 있으면 틀린 글자로 간주")
    p_oracle.add_argument("--allow", action="append", default=[], metavar="HOST")
    p_oracle.add_argument("--delay", type=float, default=_DEFAULT_DELAY,
                          help=f"요청 사이 최소 간격 초 (기본 {_DEFAULT_DELAY})")
    p_oracle.add_argument("--max", type=int, default=2000, help="총 요청 수 상한 (기본 2000)")
    p_oracle.add_argument("--timeout", type=float, default=10.0, help="타임아웃 초 (기본 10)")
    p_oracle.set_defaults(func=_oracle)

    p_po = actions.add_parser(
        "padding-oracle",
        help="CBC/PKCS7 패딩 오라클로 암호문을 복호화 (키 없이)",
    )
    p_po.add_argument("url", help=f"URL. '{_FUZZ_MARKER}' 자리에 조작한 암호문이 들어간다")
    p_po.add_argument("--cipher", required=True, metavar="B64",
                      help="복호화할 암호문 (base64)")
    p_po.add_argument("-X", "--method", default="GET", help="HTTP 메서드 (기본 GET)")
    p_po.add_argument("-H", "--header", action="append", default=[], metavar="'K: V'")
    p_po.add_argument("-d", "--data", help=f"요청 본문 (여기에도 '{_FUZZ_MARKER}' 사용 가능)")
    p_po.add_argument("--bad", metavar="REGEX",
                      help="응답 본문에 이 정규식이 있으면 '패딩 틀림'으로 판정 (예: ValueError)")
    p_po.add_argument("--ok", metavar="REGEX",
                      help="응답 본문에 이 정규식이 있으면 '패딩 맞음'으로 판정")
    p_po.add_argument("--block", type=int, default=16, help="블록 크기 바이트 (기본 16)")
    p_po.add_argument("--iv", metavar="HEX",
                      help="IV (hex). 없으면 0으로 가정하고 첫 블록을 복원 (이 챌린지는 0)")
    p_po.add_argument("--raw", action="store_true",
                      help=f"'{_FUZZ_MARKER}' 자리에 base64 를 URL 인코딩하지 않고 그대로 넣는다")
    p_po.add_argument("--allow", action="append", default=[], metavar="HOST")
    p_po.add_argument("--delay", type=float, default=0.0,
                      help="요청 사이 최소 간격 초 (기본 0)")
    p_po.add_argument("--max", type=int, default=100000,
                      help="총 요청 수 상한 (기본 100000)")
    p_po.add_argument("--timeout", type=float, default=10.0, help="타임아웃 초 (기본 10)")
    p_po.set_defaults(func=_padding_oracle)

    p_diff = actions.add_parser("diff", help="두 응답(상태·길이·본문) 비교")
    p_diff.add_argument("url1", help="기준 URL")
    p_diff.add_argument("url2", help="비교할 URL")
    p_diff.add_argument("-X", "--method", default="GET", help="두 요청 공통 메서드 (기본 GET)")
    p_diff.add_argument("-H", "--header", action="append", default=[], metavar="'K: V'")
    p_diff.add_argument("-d", "--data", help="두 요청 공통 본문")
    p_diff.add_argument("--allow", action="append", default=[], metavar="HOST")
    p_diff.add_argument("--cookies", metavar="FILE", help="쿠키 파일")
    p_diff.add_argument("--timeout", type=float, default=10.0, help="타임아웃 초 (기본 10)")
    p_diff.add_argument("--max-lines", type=int, default=40, dest="max_lines",
                        help="본문 diff 로 출력할 최대 줄 수 (기본 40)")
    p_diff.set_defaults(func=_diff)


def _compile(pattern: str | None, label: str):
    """정규식 패턴을 컴파일한다. 비어 있으면 None, 잘못되면 짧은 오류로 안내한다."""
    if not pattern:
        return None
    from ctfkit.registry import TransformError
    try:
        return re.compile(pattern)
    except re.error as e:
        raise TransformError(f"{label} 정규식이 올바르지 않습니다: {e}") from e


def _parse_headers(items: list[str]) -> dict:
    headers = {}
    for item in items:
        k, _, v = item.partition(":")
        headers[k.strip()] = v.strip()
    return headers


def _load_cookies(path):
    if not path:
        return None
    jar = LWPCookieJar(path)
    if os.path.exists(path):
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
        except OSError:
            pass
    return jar


def _save_cookies(jar, path):
    if jar is not None and path:
        jar.save(ignore_discard=True, ignore_expires=True)


def _print_response(code, body, show_headers):
    if show_headers:
        print(f"HTTP {code}  ({len(body)} 바이트)", file=sys.stderr)
    try:
        sys.stdout.write(body.decode("utf-8"))
        if body and not body.endswith(b"\n"):
            sys.stdout.write("\n")
    except UnicodeDecodeError:
        print("(텍스트가 아닌 응답이라 hex로 표시합니다)", file=sys.stderr)
        print(body.hex())


def _run_single(url, method, headers, data, args):
    try:
        _ensure_allowed(url, args.allow)
    except ValueError as e:
        from ctfkit.registry import TransformError
        raise TransformError(str(e)) from e

    jar = _load_cookies(getattr(args, "cookies", None))
    try:
        code, body = _do_request(url, method, headers, data, jar, args.timeout)
    except urllib.error.URLError as e:
        from ctfkit.registry import TransformError
        raise TransformError(f"요청 실패: {e.reason}") from e
    _save_cookies(jar, getattr(args, "cookies", None))
    _print_response(code, body, args.show_headers)
    return 0 if code < 400 else 1


def _send(args):
    return _run_single(args.url, args.method, _parse_headers(args.header), args.data, args)


def _curl(args):
    try:
        parsed = parse_curl(args.command)
    except IndexError:
        # -X 처럼 값이 필요한 옵션이 명령 끝에 값 없이 온 경우
        from ctfkit.registry import TransformError
        raise TransformError("curl 명령의 옵션에 값이 없습니다") from None
    except ValueError as e:
        from ctfkit.registry import TransformError
        raise TransformError(str(e)) from e
    return _run_single(parsed["url"], parsed["method"], parsed["headers"], parsed["data"], args)


def _diff(args):
    from ctfkit.registry import TransformError
    import difflib

    headers = _parse_headers(args.header)
    for url in (args.url1, args.url2):
        try:
            _ensure_allowed(url, args.allow)
        except ValueError as e:
            raise TransformError(str(e)) from e

    jar = _load_cookies(args.cookies)
    try:
        code1, body1 = _do_request(args.url1, args.method, headers, args.data, jar, args.timeout)
        code2, body2 = _do_request(args.url2, args.method, headers, args.data, jar, args.timeout)
    except urllib.error.URLError as e:
        raise TransformError(f"요청 실패: {e.reason}") from e
    _save_cookies(jar, args.cookies)

    print(f"상태   : {code1} vs {code2}" + ("   (다름)" if code1 != code2 else ""))
    delta = len(body2) - len(body1)
    print(f"길이   : {len(body1)} vs {len(body2)}   (Δ{delta:+})")
    if body1 == body2:
        print("본문   : 동일")
        return 0

    t1 = body1.decode("utf-8", "replace").splitlines()
    t2 = body2.decode("utf-8", "replace").splitlines()
    diff = list(difflib.unified_diff(t1, t2, fromfile="url1", tofile="url2", lineterm=""))
    added = sum(1 for ln in diff if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in diff if ln.startswith("-") and not ln.startswith("---"))
    print(f"본문   : 다름 (+{added} / -{removed} 줄)")
    for ln in diff[:args.max_lines]:
        print(ln)
    if len(diff) > args.max_lines:
        print(f"... ({len(diff) - args.max_lines} 줄 더 있음, --max-lines 로 늘리기)")
    return 0


def _fuzz(args):
    from ctfkit.registry import TransformError

    if _FUZZ_MARKER not in args.url and (not args.data or _FUZZ_MARKER not in args.data):
        raise TransformError(f"URL 또는 --data 에 '{_FUZZ_MARKER}' 치환 지점이 있어야 합니다")
    if args.max < 1:
        raise TransformError("--max 는 1 이상이어야 합니다")

    # allowlist 는 마커를 뺀 URL 로 먼저 검사한다 (모든 단어가 같은 호스트를 향하므로)
    try:
        _ensure_allowed(args.url.replace(_FUZZ_MARKER, "x"), args.allow)
    except ValueError as e:
        raise TransformError(str(e)) from e

    try:
        with open(args.words, "rb") as f:
            words = [w.rstrip(b"\r\n").decode("utf-8", "replace") for w in f if w.strip()]
    except OSError as e:
        raise TransformError(f"워드리스트를 읽을 수 없습니다: {e}") from e

    if len(words) > args.max:
        print(f"[!] 단어 {len(words)}개 중 상한({args.max})까지만 시도합니다.", file=sys.stderr)
        words = words[:args.max]

    try:
        hide = {int(c) for c in args.hide.split(",")} if args.hide else set()
    except ValueError:
        raise TransformError(f"--hide 는 쉼표로 구분한 상태코드여야 합니다: {args.hide}") from None
    match_re = _compile(getattr(args, "match", None), "--match")
    fail_re = _compile(getattr(args, "fail", None), "--fail")
    headers = _parse_headers(args.header)
    hits = 0
    for n, word in enumerate(words):
        if n:
            time.sleep(args.delay)
        url = args.url.replace(_FUZZ_MARKER, word)
        data = args.data.replace(_FUZZ_MARKER, word) if args.data else None
        try:
            code, body = _do_request(url, args.method, headers, data, None, args.timeout)
        except urllib.error.URLError as e:
            print(f"  {word:<24} 실패: {e.reason}", file=sys.stderr)
            continue
        if code in hide:
            continue
        if match_re is not None or fail_re is not None:
            text = body.decode("utf-8", "replace")
            if match_re is not None and not match_re.search(text):
                continue
            if fail_re is not None and fail_re.search(text):
                continue
        hits += 1
        print(f"  {word:<24} HTTP {code}  {len(body)} 바이트")
    print(f"[+] {len(words)}개 요청, 표시된 응답 {hits}개", file=sys.stderr)
    return 0


def _oracle(args):
    """접두사 비교 취약점(예: secret[0:len(guess)] == guess)을 한 글자씩 자동 복구한다.

    각 자리마다 charset 의 글자를 (지금까지 복구한 접두사 + 글자) 로 붙여 보내고,
    --success / --fail 로 '맞은 접두사'인지 판별한다. 맞는 글자를 찾으면 다음 자리로 넘어가고,
    어떤 글자도 맞지 않으면(= 더 늘릴 수 없으면) 복구를 끝낸다.
    """
    from ctfkit.registry import TransformError

    if _FUZZ_MARKER not in args.url and (not args.data or _FUZZ_MARKER not in args.data):
        raise TransformError(f"URL 또는 --data 에 '{_FUZZ_MARKER}' 치환 지점이 있어야 합니다")
    if not args.success and not args.fail:
        raise TransformError("--success 또는 --fail 중 하나 이상으로 정답 판별 기준을 정하세요")
    if args.max_length < 1:
        raise TransformError("--max-length 는 1 이상이어야 합니다")
    if args.max < 1:
        raise TransformError("--max 는 1 이상이어야 합니다")
    if not args.charset:
        raise TransformError("--charset 이 비어 있습니다")

    # allowlist 는 마커를 뺀 URL 로 먼저 검사한다
    try:
        _ensure_allowed(args.url.replace(_FUZZ_MARKER, "x"), args.allow)
    except ValueError as e:
        raise TransformError(str(e)) from e

    success_re = _compile(args.success, "--success")
    fail_re = _compile(args.fail, "--fail")
    headers = _parse_headers(args.header)

    def accepted(body: bytes) -> bool:
        text = body.decode("utf-8", "replace")
        if success_re is not None and not success_re.search(text):
            return False
        if fail_re is not None and fail_re.search(text):
            return False
        return True

    sent = 0
    recovered = ""
    stopped_by_cap = False
    for _pos in range(args.max_length):
        found = None
        for ch in args.charset:
            if sent >= args.max:
                stopped_by_cap = True
                break
            if sent:
                time.sleep(args.delay)
            candidate = recovered + ch
            url = args.url.replace(_FUZZ_MARKER, candidate)
            data = args.data.replace(_FUZZ_MARKER, candidate) if args.data else None
            sent += 1
            try:
                _code, body = _do_request(url, args.method, headers, data, None, args.timeout)
            except urllib.error.URLError as e:
                raise TransformError(f"요청 실패: {e.reason}") from e
            if accepted(body):
                found = ch
                break
        if stopped_by_cap or found is None:
            break
        recovered += found
        print(f"  [{len(recovered)}] {recovered}", file=sys.stderr)

    if not recovered:
        print(f"[-] 복구 실패: 어떤 글자도 조건에 맞지 않았습니다. (요청 {sent}개)", file=sys.stderr)
        return 1
    if stopped_by_cap:
        print(f"[!] 요청 상한(--max {args.max})에 도달해 중단했습니다.", file=sys.stderr)
    print(f"[+] 복구한 값: {recovered}  (요청 {sent}개)", file=sys.stderr)
    print(recovered)
    return 0


def _strip_pkcs7(data: bytes, block: int) -> tuple[bytes, bool]:
    """PKCS7 패딩을 떼어낸다. 유효하면 (평문, True), 아니면 (원본, False)."""
    if not data or len(data) % block != 0:
        return data, False
    p = data[-1]
    if p < 1 or p > block or data[-p:] != bytes([p]) * p:
        return data, False
    return data[:-p], True


def _padding_oracle(args):
    """CBC/PKCS7 패딩 오라클로 암호문을 블록 단위로 복호화한다 (키 불필요).

    각 타깃 블록 C_t 앞에 조작 블록 X 를 붙인 [X][C_t] 를 보내고, 패딩이 맞는 X 를 찾아
    중간값 D(C_t) 를 한 바이트씩 복원한다. 평문 P_t = D(C_t) XOR (이전 블록, 첫 블록은 IV).
    """
    from ctfkit.registry import TransformError

    marker_in_url = _FUZZ_MARKER in args.url
    marker_in_data = bool(args.data) and _FUZZ_MARKER in args.data
    if not marker_in_url and not marker_in_data:
        raise TransformError(f"URL 또는 --data 에 '{_FUZZ_MARKER}' 치환 지점이 있어야 합니다")
    if not args.bad and not args.ok:
        raise TransformError("--bad 또는 --ok 중 하나 이상으로 패딩 판별 기준을 정하세요")
    if args.block < 2:
        raise TransformError("--block 은 2 이상이어야 합니다")
    if args.max < 1:
        raise TransformError("--max 는 1 이상이어야 합니다")

    block = args.block
    try:
        cipher = base64.b64decode(args.cipher, validate=True)
    except (binascii.Error, ValueError) as e:
        raise TransformError(f"--cipher 가 올바른 base64 가 아닙니다: {e}") from e
    if len(cipher) == 0 or len(cipher) % block != 0:
        raise TransformError(f"암호문 길이({len(cipher)})가 블록 크기({block})의 배수가 아닙니다")

    iv_known = args.iv is not None
    if iv_known:
        try:
            iv = bytes.fromhex(args.iv.replace(" ", ""))
        except ValueError as e:
            raise TransformError(f"--iv 가 올바른 hex 가 아닙니다: {e}") from e
        if len(iv) != block:
            raise TransformError(f"--iv 길이는 블록 크기({block})와 같아야 합니다")
    else:
        iv = bytes(block)
        print("[!] --iv 미지정: IV 를 0 으로 가정하고 첫 블록을 복원합니다.", file=sys.stderr)

    try:
        _ensure_allowed(args.url.replace(_FUZZ_MARKER, "x"), args.allow)
    except ValueError as e:
        raise TransformError(str(e)) from e

    bad_re = _compile(args.bad, "--bad")
    ok_re = _compile(args.ok, "--ok")
    headers = _parse_headers(args.header)
    sent = [0]

    def valid_pad(body: bytes) -> bool:
        text = body.decode("utf-8", "replace")
        if ok_re is not None and not ok_re.search(text):
            return False
        if bad_re is not None and bad_re.search(text):
            return False
        return True

    def submit(raw: bytes) -> bool:
        if sent[0] >= args.max:
            raise TransformError(f"요청 상한(--max {args.max})에 도달했습니다. 필요하면 --max 를 올리세요")
        if sent[0] and args.delay:
            time.sleep(args.delay)
        token = base64.b64encode(raw).decode("ascii")
        if not args.raw:
            token = quote(token, safe="")
        url = args.url.replace(_FUZZ_MARKER, token)
        data = args.data.replace(_FUZZ_MARKER, token) if args.data else None
        sent[0] += 1
        try:
            _code, body = _do_request(url, args.method, headers, data, None, args.timeout)
        except urllib.error.URLError as e:
            raise TransformError(f"요청 실패: {e.reason}") from e
        return valid_pad(body)

    def recover_intermediate(target: bytes) -> bytearray:
        inter = bytearray(block)
        for pad in range(1, block + 1):
            pos = block - pad
            found = False
            for guess in range(256):
                x = bytearray(block)
                for j in range(pos + 1, block):
                    x[j] = inter[j] ^ pad
                x[pos] = guess
                if not submit(bytes(x) + target):
                    continue
                if pad == 1:
                    # \x01 처럼 보이지만 사실 \x02\x02... 인 오탐 방지: 앞 바이트를 바꿔 재확인
                    x2 = bytearray(x)
                    x2[pos - 1] ^= 0xFF
                    if not submit(bytes(x2) + target):
                        continue
                inter[pos] = guess ^ pad
                found = True
                break
            if not found:
                raise TransformError(
                    f"패딩이 맞는 바이트를 찾지 못했습니다 (블록 위치 {pos}). "
                    f"--bad/--ok 판별 기준이나 블록 크기를 확인하세요."
                )
        return inter

    n = len(cipher) // block
    plain = bytearray()
    for t in range(n):
        target = cipher[t * block:(t + 1) * block]
        prev = iv if t == 0 else cipher[(t - 1) * block:t * block]
        inter = recover_intermediate(target)
        block_pt = bytes(inter[i] ^ prev[i] for i in range(block))
        plain += block_pt
        print(f"  [블록 {t + 1}/{n}] {block_pt.hex()}", file=sys.stderr)

    stripped, ok = _strip_pkcs7(bytes(plain), block)
    if not ok:
        print("[!] PKCS7 패딩이 유효하지 않아 패딩을 떼지 않고 그대로 보여줍니다.", file=sys.stderr)
    result = stripped
    print(f"[+] 복호화 완료 (블록 {n}개, 요청 {sent[0]}개)", file=sys.stderr)
    print(f"hex: {result.hex()}", file=sys.stderr)
    sys.stdout.write(result.decode("utf-8", "replace"))
    if result and not result.endswith(b"\n"):
        sys.stdout.write("\n")
    return 0
