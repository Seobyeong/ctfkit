"""ctfkit web: 워게임 서버 대상 HTTP 요청 / curl 재현 / 파라미터 퍼징.

안전장치 (README의 윤리 규정을 코드로 강제):
  - allowlist 밖 호스트로는 절대 요청하지 않는다 (기본: localhost, *.dreamhack.games).
  - 반복 요청에는 요청 간 최소 간격(--delay)과 총량 상한(--max)을 둔다.
표준 라이브러리(urllib, http.cookiejar)만 사용한다.
"""

import os
import shlex
import sys
import time
import urllib.error
import urllib.request
from http.cookiejar import LWPCookieJar
from urllib.parse import urlparse

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
        "actions": {"send": "요청", "curl": "curl 재현", "fuzz": "퍼징"},
        "fields": {
            "url": {"label": "URL"},
            "fuzz.url": {"label": f"URL ({_FUZZ_MARKER} 위치 표시)"},
            "command": {"label": "curl 명령", "kind": "text"},
            "method": {"label": "메서드", "suggest": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]},
            "header": {"label": "헤더 (한 줄에 하나)"},
            "data": {"label": "본문"},
            "allow": {"label": "허용 호스트 추가", "kind": "entry"},
            "cookies": {"label": "쿠키 파일"},
            "words": {"label": "워드리스트"},
            "hide": {"label": "숨길 상태코드"},
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
    p_fuzz.set_defaults(func=_fuzz)


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
        hits += 1
        print(f"  {word:<24} HTTP {code}  {len(body)} 바이트")
    print(f"[+] {len(words)}개 요청, 표시된 응답 {hits}개", file=sys.stderr)
    return 0
