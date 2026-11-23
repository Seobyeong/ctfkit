"""ctfkit template: 분야별 풀이 스크립트 뼈대를 만든다. 만들기만 하고 실행하지 않는다.

자동으로 풀리지 않는 문제는 결국 스크립트를 짠다. 그때마다 같은 머리말(접속 코드, 바이너리 불러오기, 세션,
정수 변환)을 다시 쓰고, 분석에서 본 값(아키텍처, PIE, 카나리)을 옮겨 적는다. template 은 그 부분을 채워 준다.

  template pwn FILE        보호 기법·아키텍처·눈에 띄는 함수가 채워진 pwntools 스크립트
  template web URL         세션·기본 요청·플래그 검색이 잡힌 requests 스크립트
  template remote SOURCE   서버 소스의 주고받는 순서가 채워진 소켓 스크립트 (nc 로 접속하는 문제)
  template rsa -n -e -c    값이 변수로 들어가고 흔한 공격 함수가 붙은 표준 라이브러리 스크립트

결과는 stdout 으로 낸다 (`> solve.py` 로 저장). -o 를 주면 파일로 쓰고, 이미 있으면 --force 없이는 덮어쓰지 않는다.
스크립트에 넣는 값은 모두 repr() 로 넣는다. 파일 이름에 따옴표가 있어도 생성된 코드의 문법이 깨지지 않는다.
"""

import os
import re

from ctfkit import __version__
from ctfkit.console import log
from ctfkit.flags import default_pattern
from ctfkit.registry import TransformError

GUI_HINTS = {
    "template": {
        "label": "풀이 뼈대",
        "order": 48,
        "group": "파일·바이너리",
        "desc": "pwntools·requests·RSA 풀이 스크립트 뼈대를 만듭니다 (실행하지 않음).",
        "actions": {"pwn": "pwn (pwntools)", "web": "web (requests)", "remote": "nc 접속 (소켓)", "rsa": "RSA"},
        "fields": {
            "file": {"label": "바이너리 파일", "kind": "file"},
            "source": {"label": "서버 소스", "kind": "file"},
            "url": {"label": "문제 주소"},
            "host": {"label": "원격 호스트 (주소를 그대로 붙여 넣어도 됨)"},
            "port": {"label": "원격 포트"},
            "output": {"label": "저장할 파일 (비우면 화면에)"},
            "force": {"label": "있으면 덮어쓰기"},
        },
    },
}

# pwntools context.arch 이름 (binfmt 의 아키텍처 키 → pwntools)
_PWN_ARCH = {"x64": "amd64", "x86": "i386", "arm": "arm", "arm64": "aarch64", "mips": "mips", "riscv": "riscv64"}
# 출제자가 "여기로 뛰어라" 고 둔 함수 이름에 흔한 말
_WIN_NAME = re.compile(r"win|flag|shell|backdoor|secret|hidden|admin", re.IGNORECASE)
_OVERFLOW = ("gets", "strcpy", "strcat", "sprintf", "scanf", "__isoc99_scanf", "read", "fgets", "memcpy")
_FORMAT = ("printf", "fprintf", "dprintf")
_SAFE_NAME = re.compile(r"[A-Za-z_][\w.@]{0,99}")


def register(subparsers):
    parser = subparsers.add_parser("template", help="풀이 스크립트 뼈대 생성 (pwn / web / remote / rsa, 실행하지 않음)")
    actions = parser.add_subparsers(dest="action", required=True, metavar="<action>")

    def _out(p):
        p.add_argument("-o", "--output", help="이 파일로 저장 (기본: 화면에 출력)")
        p.add_argument("--force", action="store_true", help="-o 파일이 이미 있으면 덮어쓰기")

    p = actions.add_parser("pwn", help="pwntools 스크립트 (보호 기법·아키텍처·함수 주소 채움)")
    p.add_argument("file", help="ELF 바이너리")
    p.add_argument("--host", default="localhost", help="원격 호스트 (기본 localhost)")
    p.add_argument("--port", type=int, default=0, help="원격 포트")
    _out(p)
    p.set_defaults(func=_pwn)

    p = actions.add_parser("web", help="requests 스크립트 (세션·기본 요청·플래그 검색)")
    p.add_argument("url", help="문제 주소 (예: http://host1.dreamhack.games:12345/)")
    _out(p)
    p.set_defaults(func=_web)

    p = actions.add_parser("remote", help="nc 로 접속하는 문제의 소켓 스크립트 (서버 소스의 주고받는 순서를 채움)")
    p.add_argument("source", help="문제의 서버 소스 (예: prob.py)")
    p.add_argument("--host", default="localhost", help="원격 호스트 (기본 localhost)")
    p.add_argument("--port", type=int, default=0, help="원격 포트")
    _out(p)
    p.set_defaults(func=_remote)

    p = actions.add_parser("rsa", help="RSA 풀이 스크립트 (값을 변수로, 흔한 공격 함수 포함)")
    p.add_argument("-n", help="모듈러스 n (10진수 또는 0x..)")
    p.add_argument("-e", default=None, help="공개 지수 e (기본 65537)")
    p.add_argument("-c", help="암호문 c")
    p.add_argument("--values", metavar="JSON",
                   help="start 가 만든 values.json 에서 n·e·c 를 읽는 스크립트로 (숫자를 스크립트에 적지 않는다)")
    _out(p)
    p.set_defaults(func=_rsa)


def _header(kind: str, needs: str) -> str:
    return (f"#!/usr/bin/env python3\n"
            f"# ctfkit {__version__} template {kind} 로 만든 뼈대. ctfkit 은 이 스크립트를 실행하지 않는다.\n"
            f"# 필요: {needs}\n")


def _emit(text: str, args) -> int:
    if not args.output:
        print(text, end="")
        return 0
    if os.path.exists(args.output) and not args.force:
        raise TransformError(f"이미 있는 파일입니다: {args.output} (--force 로 덮어쓰기)")
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    log(f"[+] 저장: {args.output}")
    return 0


# ---------------------------------------------------------------- pwn

def pwn_facts(data: bytes) -> dict:
    """ELF 를 분석해 스크립트에 넣을 값을 모은다. 실행 파일이 아니면 TransformError."""
    from ctfkit import binfmt
    from ctfkit.commands.pwn import elf_protections

    info = binfmt.parse(data)
    if info.fmt != "ELF":
        raise TransformError("template pwn 은 ELF 만 지원합니다 (pwntools 기준)")
    prot = dict(elf_protections(info))
    # 심볼 이름은 출제자가 정한다. 줄바꿈이 든 이름이 주석을 빠져나와 코드가 되지 않게 식별자 모양만 쓴다
    funcs = {s.name: s.addr for s in info.symbols if s.kind == "FUNC" and _SAFE_NAME.fullmatch(s.name)}
    return {
        "arch": _PWN_ARCH.get(info.arch or "", "amd64"),
        "bits": info.bits,
        "endian": info.endian,
        "pie": prot["PIE"] == "켜짐",
        "canary": prot["Canary"] == "켜짐",
        "nx": prot["NX"] != "꺼짐(실행 가능 스택)",   # 표시가 없으면 대부분 커널이 NX 로 다룬다
        "relro": prot["RELRO"].split(" (")[0].replace("없음", "No RELRO"),
        # 주소가 0 이면 다른 라이브러리에서 가져오는 함수(import)다
        "wins": sorted(name for name, addr in funcs.items()
                       if addr and _WIN_NAME.search(name) and not name.startswith("_")),
        "overflow": sorted(name for name in funcs if name in _OVERFLOW),
        "format": sorted(name for name in funcs if name in _FORMAT),
        "system": "system" in funcs,
        "addrs": funcs,
    }


def _libs(binary: str) -> tuple[str | None, str | None]:
    """바이너리 옆에 함께 준 libc·로더 파일."""
    folder = os.path.dirname(os.path.abspath(binary))
    libc = ld = None
    for name in sorted(os.listdir(folder)):
        if libc is None and re.match(r"libc[.-].*so", name):
            libc = name
        elif ld is None and re.match(r"ld[.-].*so", name):
            ld = name
    return _script_path(os.path.join(os.path.dirname(binary), libc)) if libc else None, \
        _script_path(os.path.join(os.path.dirname(binary), ld)) if ld else None


def _script_path(path: str) -> str:
    """스크립트에 넣을 경로. 폴더 없는 이름은 ./ 를 붙인다 (process() 가 PATH 에서 찾지 않게)."""
    path = path.replace(os.sep, "/")
    if not os.path.isabs(path) and not path.startswith(("./", "../")):
        path = "./" + path
    return path


def render_pwn(binary: str, facts: dict, host: str = "localhost", port: int = 0,
               libc: str | None = None, ld: str | None = None) -> str:
    f = facts
    path = _script_path(binary)
    lines = [_header("pwn", "pip install pwntools  (리눅스 또는 WSL)"),
             f"# 분석: {f['arch']} {f['bits']}-bit {f['endian']}, PIE {'켜짐' if f['pie'] else '꺼짐'}, "
             f"Canary {'켜짐' if f['canary'] else '꺼짐'}, NX {'켜짐' if f['nx'] else '꺼짐'}, {f['relro']}",
             "# 실행: python3 solve.py            (로컬)",
             "#       python3 solve.py REMOTE     (원격)   python3 solve.py GDB  (gdb 붙여서)",
             "from pwn import *",
             "",
             f"BINARY = {path!r}",
             f"HOST, PORT = args.HOST or {host!r}, int(args.PORT or {port!r})",
             "",
             f"ARCH = {f['arch']!r}",
             f"PIE = {f['pie']!r}",
             f"CANARY = {f['canary']!r}",
             f"NX = {f['nx']!r}",
             f"RELRO = {f['relro']!r}",
             "",
             "context.binary = elf = ELF(BINARY, checksec=False)",
             "context.arch = ARCH",
             "context.log_level = args.LOG_LEVEL or 'info'"]
    if libc:
        lines.append(f"libc = ELF({libc!r}, checksec=False)   # 문제와 함께 준 libc")
    lines += ["", "GDBSCRIPT = '''", "b *main" if "main" in f["addrs"] else "# b *<주소>  (심볼 없음)",
              "continue", "'''", "", "",
              "def start():",
              "    if args.REMOTE:",
              "        return remote(HOST, PORT)",
              "    if args.GDB:",
              "        return gdb.debug(BINARY, gdbscript=GDBSCRIPT)"]
    if ld and libc:
        lines.append(f"    return process([{ld!r}, BINARY], env={{'LD_PRELOAD': {libc!r}}})")
    else:
        lines.append("    return process(BINARY)")

    # 분석에서 본 것에 따른 단서
    hints = []
    if f["overflow"]:
        hints.append(f"입력 함수 {', '.join(f['overflow'])}: 스택 오버플로 후보. 오프셋은 아래 OFFSET")
    if f["format"]:
        hints.append(f"{', '.join(f['format'])}: 사용자 입력이 서식 문자열로 들어가면 포맷 스트링 (fmtstr_payload)")
    if f["wins"]:
        names = ", ".join(f"{w}" + ("" if f["pie"] else f" {f['addrs'][w]:#x}") for w in f["wins"])
        hints.append(f"눈에 띄는 함수: {names}" + (" (PIE 라 주소 유출 후 elf.address 를 맞춰야 한다)" if f["pie"] else ""))
    if f["canary"]:
        hints.append("Canary 켜짐: 덮기 전에 카나리를 유출해야 한다 (포맷 스트링, 마지막 널 바이트 덮어 출력 등)")
    if not f["nx"]:
        hints.append("NX 꺼짐: 스택에 셸코드를 올릴 수 있다 (asm(shellcraft.sh()))")
    if f["system"]:
        hints.append("system 을 쓴다: elf.plt.system 과 '/bin/sh' 문자열로 ret2plt 가능성")
    if not f["pie"] and f["relro"] != "Full RELRO":
        hints.append("PIE 꺼짐 + Full RELRO 아님: GOT 덮어쓰기 가능성 (elf.got)")
    lines += ["", "", "# 단서 (ctfkit 정적 분석)"] + [f"# - {h}" for h in hints or ["(특이점 없음)"]]

    target = f["wins"][0] if f["wins"] else None
    lines += ["", "# 크래시 값으로 오프셋 찾기: ctfkit pwn cyclic 200 → 입력 → ctfkit pwn cyclic -l <rip/eip 값>",
              "OFFSET = 0", "", "",
              "def exploit(io):",
              "    payload = flat({",
              "        OFFSET: ["]
    if target and not f["pie"]:
        if f["arch"] == "amd64":
            lines.append("            # ret 가젯 하나를 앞에 (amd64 에서 system 등이 movaps 정렬로 죽으면)")
        lines.append(f"            elf.sym[{target!r}],   # {f['addrs'][target]:#x}")
    else:
        lines.append("            # 돌아갈 주소, ROP 가젯 (ctfkit pwn rop BINARY -f 'pop rdi')")
    lines += ["        ],",
              "    })",
              "    io.sendlineafter(b':', payload)   # 프롬프트에 맞게 고친다",
              "    io.interactive()",
              "", "",
              "if __name__ == '__main__':",
              "    exploit(start())",
              ""]
    return "\n".join(lines)


def _pwn(args):
    with open(args.file, "rb") as fh:
        facts = pwn_facts(fh.read())
    libc, ld = _libs(args.file)
    host, port = split_address(args.host, args.port)
    return _emit(render_pwn(args.file, facts, host, port, libc, ld), args)


# ---------------------------------------------------------------- web

def render_web(url: str) -> str:
    if not re.match(r"https?://", url):
        raise TransformError(f"http:// 또는 https:// 로 시작하는 주소가 필요합니다: {url}")
    return "\n".join([
        _header("web", "pip install requests"),
        "# 허가된 대상(문제 인스턴스, 직접 띄운 서버)에만 보낸다.",
        "import re",
        "",
        "import requests",
        "",
        f"BASE = {url.rstrip('/')!r}",
        f"FLAG = re.compile({default_pattern()!r}, re.IGNORECASE)",
        "",
        "s = requests.Session()",
        "s.headers['User-Agent'] = 'Mozilla/5.0'",
        "# s.cookies.set('session', '...')          # 브라우저에서 복사한 쿠키",
        "# s.proxies = {'http': 'http://127.0.0.1:8080'}   # Burp 로 보기",
        "",
        "",
        "def get(path='/', **kw):",
        "    r = s.get(BASE + path, timeout=10, **kw)",
        "    show(r)",
        "    return r",
        "",
        "",
        "def post(path='/', data=None, **kw):",
        "    r = s.post(BASE + path, data=data, timeout=10, **kw)",
        "    show(r)",
        "    return r",
        "",
        "",
        "def show(r):",
        "    print(r.status_code, r.request.method, r.url, len(r.content), 'bytes')",
        "    for flag in FLAG.findall(r.text):",
        "        print('[FLAG]', flag)",
        "",
        "",
        "if __name__ == '__main__':",
        "    r = get('/')",
        "    print(r.text[:500])",
        "    # r = post('/login', {'username': 'admin', 'password': \"' or 1=1-- -\"})",
        "",
    ])


def _web(args):
    return _emit(render_web(args.url), args)


# ---------------------------------------------------------------- remote (nc 로 접속하는 문제)

def server_steps(text: str) -> list[tuple[str, bytes, str]]:
    """파이썬 서버 소스에서 주고받는 순서를 뽑는다: [(종류, 앞 글자, 원래 코드 한 줄)].

    종류는 "value" (print(f"앞 글자{값}") — 앞 글자 뒤의 값을 읽는다) 와 "input" (input("앞 글자") — 보낼 차례).
    파이썬이 아니거나 문법이 깨졌으면 빈 목록. 반복문·분기는 따지지 않고 소스에 나온 순서대로, 같은 것은 한 번만 둔다.
    """
    import ast

    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    steps, seen = [], set()
    for node in sorted((n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)),
                       key=lambda n: (n.lineno, n.col_offset)):
        arg = node.args[0] if node.args else None
        if node.func.id == "input":
            prefix = arg.value if isinstance(arg, ast.Constant) and isinstance(arg.value, str) else ""
            kind = "input"
        elif node.func.id == "print" and isinstance(arg, ast.JoinedStr) and len(arg.values) >= 2 \
                and isinstance(arg.values[0], ast.Constant) and isinstance(arg.values[1], ast.FormattedValue):
            prefix, kind = arg.values[0].value, "value"
        else:
            continue
        code = (ast.get_source_segment(text, node) or "").replace("\r", " ").replace("\n", " ")[:100]
        if (kind, prefix) in seen:
            continue
        seen.add((kind, prefix))
        steps.append((kind, prefix.encode("utf-8", "replace"), code))
    return steps


def render_remote(source_name: str, text: str, host: str = "localhost", port: int = 0) -> str:
    from ctfkit import source as source_mod

    steps = server_steps(text)
    info = source_mod.analyze(text, source_name)
    limit = re.search(r"\balarm\(\s*(\d+)\s*\)", text)
    body, n = [], 0
    for kind, prefix, code in steps:
        if kind == "value":
            n += 1
            body.append(f"    v{n} = value_after(io, {prefix!r})   # {code}")
        else:
            wait = f"io.recvuntil({prefix!r})" if prefix else "pass   # 안내 글 없이 입력을 받는다"
            body += [f"    # {code}", f"    {wait}", "    io.sendline(b'')   # TODO: 보낼 값"]
    if not body:
        body = ["    print(io.recvline())", "    io.sendline(b'')   # TODO: 보낼 값"]

    lines = [_header("remote", "파이썬 3.8 이상 (표준 라이브러리만, pwntools 없이 동작)"),
             f"# 서버 소스: {os.path.basename(source_name)!r}"]
    if info and info.clues:
        lines.append("# 단서 (ctfkit): " + ", ".join(info.clues))
    if limit:
        lines.append(f"# 서버 시간 제한 {limit.group(1)}초: 오래 걸리는 계산은 접속 전에 미리 해 둔다")
    lines += [
        "import re",
        "import socket",
        "import sys",
        "",
        f"HOST = {host!r}",
        f"PORT = {port!r}",
        f"FLAG = re.compile({default_pattern()!r}, re.IGNORECASE)",
        "",
        "",
        "def echo(data):",
        "    text = data.decode('latin-1')",
        "    sys.stdout.write(text)",
        "    for flag in FLAG.findall(text):",
        "        print('\\n[FLAG]', flag)",
        "",
        "",
        "class Remote:",
        "    def __init__(self, host, port, timeout=10):",
        "        self.sock = socket.create_connection((host, port), timeout=timeout)",
        "        self.buf = b''",
        "",
        "    def recvuntil(self, delim):",
        "        while delim not in self.buf:",
        "            chunk = self.sock.recv(4096)",
        "            if not chunk:",
        "                raise EOFError(self.buf)",
        "            self.buf += chunk",
        "        i = self.buf.index(delim) + len(delim)",
        "        out, self.buf = self.buf[:i], self.buf[i:]",
        "        echo(out)",
        "        return out",
        "",
        "    def recvline(self):",
        "        return self.recvuntil(b'\\n')",
        "",
        "    def sendline(self, data):",
        "        if isinstance(data, str):",
        "            data = data.encode()",
        "        self.sock.sendall(data + b'\\n')",
        "",
        "    def recvall(self):",
        "        try:",
        "            while True:",
        "                chunk = self.sock.recv(4096)",
        "                if not chunk:",
        "                    break",
        "                self.buf += chunk",
        "        except socket.timeout:",
        "            pass",
        "        out, self.buf = self.buf, b''",
        "        echo(out)",
        "        return out",
        "",
        "",
        "def value_after(io, prefix):",
        "    \"\"\"prefix 뒤에 오는 한 줄을 글자로 돌려준다 (예: 'N: 1234' → '1234').\"\"\"",
        "    io.recvuntil(prefix)",
        "    return io.recvline().strip().decode()",
        "",
        "",
        "if __name__ == '__main__':",
        "    io = Remote(HOST, PORT)",
        "    # 아래는 서버 소스에 나온 순서다. 반복문·메뉴는 직접 맞춘다",
    ] + body + [
        "    io.recvall()",
        "",
    ]
    return "\n".join(lines)


def _remote(args):
    try:
        with open(args.source, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        raise TransformError(f"파일을 읽을 수 없습니다: {e}") from e
    host, port = split_address(args.host, args.port)
    return _emit(render_remote(args.source, text, host, port), args)


def split_address(host: str, port: int = 0) -> tuple[str, int]:
    """드림핵이 보여 주는 주소를 그대로 넣어도 되게 한다.

    "http://host3.dreamhack.games:17980/" 이나 "host3.dreamhack.games:17980", "nc host 17980" 을 (호스트, 포트)로 나눈다.
    --port 를 따로 주면 그것이 우선한다.
    """
    text = host.strip()
    m = re.fullmatch(r"nc\s+(\S+)\s+(\d+)", text)
    if m:
        return m.group(1), port or int(m.group(2))
    text = re.sub(r"^[a-zA-Z][\w+.-]*://", "", text).split("/")[0]
    m = re.fullmatch(r"([^:\s]+):(\d+)", text)
    if m:
        return m.group(1), port or int(m.group(2))
    return text or "localhost", port


# ---------------------------------------------------------------- rsa

def rsa_notes(n: int, e: int, c: int) -> list[str]:
    """값만 보고 바로 알 수 있는 단서 (계산이 가벼운 것만)."""
    from ctfkit.rsautil import iroot

    notes = [f"n 은 {n.bit_length()} 비트"]
    if c >= n:
        notes.append("c >= n: 값이 뒤바뀌지 않았는지 확인")
    if e <= 17:
        _, exact = iroot(c, e)
        if exact:
            notes.append(f"작은 e: c 의 {e}제곱근이 정확히 떨어진다 → small_e() 로 바로 풀린다")
        else:
            notes.append("작은 e: 패딩이 없으면 c + k*n 의 e제곱근 (small_e(k_max=...))")
    if e.bit_length() > n.bit_length() * 3 // 4:
        notes.append("e 가 n 만큼 크다: 비너 공격 후보 (ctfkit rsa wiener)")
    notes.append("소인수: ctfkit rsa factor N (작은 소인수, 페르마) 또는 factordb.com")
    return notes


def render_rsa(n: int, e: int, c: int, values: tuple | None = None) -> str:
    """values 를 주면 (json 경로, n 이름, e 이름 또는 None, c 이름): 숫자 대신 그 파일에서 읽는 코드를 넣는다.

    큰 정수(2048비트 n 은 600자가 넘는다)를 에이전트가 스크립트에 옮겨 적으면 그만큼 출력 토큰을 쓴다.
    """
    if values:
        path, kn, ke, kc = values
        head = ["import json",
                "from math import gcd, isqrt",
                "",
                f"V = json.load(open({path!r}))   # ctfkit start 가 만든 값 파일",
                f"n = V[{kn!r}]",
                f"e = V[{ke!r}]" if ke else f"e = {e}",
                f"c = V[{kc!r}]"]
    else:
        head = ["from math import gcd, isqrt",
                "",
                f"n = {n}",
                f"e = {e}",
                f"c = {c}"]
    lines = [_header("rsa", "파이썬 3.8 이상 (표준 라이브러리만)")] + head + [
             "",
             "# 단서 (ctfkit)"] + [f"# - {note}" for note in rsa_notes(n, e, c)] + [
             "",
             "",
             "def to_bytes(m):",
             "    return m.to_bytes((m.bit_length() + 7) // 8, 'big')",
             "",
             "",
             "def decrypt(p, q):",
             "    assert p * q == n",
             "    d = pow(e, -1, (p - 1) * (q - 1))",
             "    return to_bytes(pow(c, d, n))",
             "",
             "",
             "def iroot(x, k):",
             "    lo, hi = 0, 1 << (x.bit_length() // k + 1)",
             "    while lo < hi:",
             "        mid = (lo + hi + 1) // 2",
             "        lo, hi = (mid, hi) if mid ** k <= x else (lo, mid - 1)",
             "    return lo, lo ** k == x",
             "",
             "",
             "def small_e(k_max=0):",
             "    for k in range(k_max + 1):",
             "        m, exact = iroot(c + k * n, e)",
             "        if exact:",
             "            return to_bytes(m)",
             "",
             "",
             "def fermat(steps=1_000_000):",
             "    a = isqrt(n) + (isqrt(n) ** 2 != n)",
             "    for _ in range(steps):",
             "        b, exact = iroot(a * a - n, 2)",
             "        if exact:",
             "            return a - b, a + b",
             "        a += 1",
             "",
             "",
             "if __name__ == '__main__':",
             "    print(small_e())",
             "    pq = fermat(100_000)",
             "    if pq:",
             "        print(decrypt(*pq))",
             "    # print(decrypt(p, q))   # 소인수를 구했으면",
             "    # print(gcd(n, n2))      # 다른 n 과 공통 인수가 있는지",
             ""]
    return "\n".join(lines)


def _rsa(args):
    from ctfkit.commands.rsa import _int

    keys = None
    if args.values:
        n, e, c, keys = _from_values(args.values, args.e)
    else:
        if args.n is None or args.c is None:
            raise TransformError("-n 과 -c 를 주거나 --values 로 값 파일을 주세요")
        n, e, c = _int(args.n, "n"), _int(args.e or "65537", "e"), _int(args.c, "c")
    if n < 2 or e < 1 or c < 0:
        raise TransformError("n 은 2 이상, e 는 1 이상, c 는 0 이상이어야 합니다")
    return _emit(render_rsa(n, e, c, keys), args)


def _from_values(path: str, e_arg):
    """values.json 에서 n·e·c 와 그 이름. e 가 파일에 없으면 -e (없으면 65537)."""
    import json

    from ctfkit.brief import pick

    try:
        with open(path, encoding="utf-8") as f:
            store = json.load(f)
    except (OSError, ValueError) as err:
        raise TransformError(f"값 파일을 읽을 수 없습니다: {err}") from err
    if not isinstance(store, dict):
        raise TransformError("값 파일의 형식이 아닙니다 (이름: 정수)")
    kn, kc = pick(store, "n", "modulus", "n1"), pick(store, "c", "ct", "cipher", "ciphertext", "enc", "c1")
    ke = pick(store, "e", "exponent", "e1")
    if kn is None or kc is None:
        raise TransformError(f"값 파일에 n 과 c 가 없습니다 (있는 이름: {', '.join(k for k in store if k != '_from')})")
    e = store[ke] if ke else int(e_arg or 65537)
    return store[kn], e, store[kc], (path.replace("\\", "/"), kn, ke, kc)
