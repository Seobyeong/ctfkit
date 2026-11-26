"""실제 AI 에이전트(Claude Code)로 재는 벤치마크: ctfkit 이 있을 때와 없을 때 같은 문제를 푸는 비용.

bench/run.py 는 "에이전트가 이런 코드를 짰을 것" 이라고 가정한 비용이다. 여기서는 가정 없이 실제 에이전트를 돌린다.

  조건 A (ctfkit 없음) : ctfkit 이 설치되지 않은 가상환경의 python 을 PATH 맨 앞에 둔다. 지시문에서도 쓰지 말라고 한다.
                         실행 기록에 ctfkit 호출이 있으면 그 실행은 무효로 표시한다.
  조건 B (ctfkit 있음) : "ctfkit start 로 시작하고, 플래그가 없으면 AGENTS.md 를 읽어라" 고 지시한다.

실행마다 `claude -p --output-format stream-json` 의 마지막 결과(토큰·비용·왕복 수·시간)와 도구 호출을 기록한다.
**이 스크립트는 실행한 사람의 Claude 사용량(비용)을 쓴다.** 실행당 비용 상한은 --budget 으로 건다.

  python bench/agent.py --list
  python bench/agent.py --problems rsa-src,hex-png --repeat 1 --model sonnet --write

기본 문제는 직접 만든 모의 문제다 (플래그 DH{...}). 실제 워게임 문제는 git 이 무시하는 bench/real/ 에서 읽고,
과적합을 막으려고 개발용과 평가용을 나눈다 (bench/README.md 의 "측정 규칙"):

  bench/real/dev/   개발용. 실패를 보고 고쳐도 된다. 여기서 잰 수치는 "고친 문제로 잰 값" 이다.  --real
  bench/real/eval/  평가용. 고치기 전에 보지 않는다. 커밋한 깨끗한 상태로, 문제마다 한 번만 잰다.  --eval

  폴더 안: <이름>.zip + <이름>.flag (정답 한 줄), 또는 <이름>/ + <이름>/flag.txt. 선택으로 <이름>.note (보고서용 설명)

  원격(nc/pwn) 문제는 <이름>.server (`bin: <압축 안 실행 파일>`, 선택 `flag: <서버에 둘 파일명>`) 를 둔다.
  그러면 WSL 의 socat 으로 그 ELF 를 TCP 로 띄우고(에이전트는 127.0.0.1 로 접속), 정답은 서버 쪽에만 둔다 — 풀어야 얻는다.
  WSL + socat 이 필요하다. 실제 원격 플래그는 서버에만 있어 쓸 수 없으므로 개발자가 정한 토큰을 서버 플래그로 쓴다.

  python bench/agent.py --real --list
  python bench/agent.py --eval --repeat 3 --budget 0.5 --write

실제 문제의 기록에는 수치만 남는다: 문제 id 는 이름의 해시, 도구 호출은 도구 이름과 ctfkit 사용 여부만 저장한다.
실제 문제 파일과 플래그는 저장소에 넣지 않는다.
"""

import argparse
import hashlib
import json
import os
import random
import re
import shlex
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import time
import venv
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctfkit import __version__, rsautil  # noqa: E402
from bench.agent_logs import PARTS, coarse, cost_breakdown  # noqa: E402

RESULTS = ROOT / "bench" / "agent_results.jsonl"
REPORT = ROOT / "bench" / "AGENT.md"
REAL_DIR = ROOT / "bench" / "real" / "dev"
EVAL_DIR = ROOT / "bench" / "real" / "eval"

COMMON = ("이 폴더의 chall/ 에 CTF 문제 파일이 있다. 플래그({prefix}{{...}} 형식)를 찾아라. 인터넷은 쓰지 말고 패키지도 설치하지 마라. "
          "플래그를 찾으면 답의 마지막 줄에 `FLAG: <플래그>` 만 적고 끝내라. {extra}")
EXTRA = {
    "A": "ctfkit 은 쓰지 마라. 파이썬 표준 라이브러리와 일반 셸 명령은 써도 된다.",
    "B": "ctfkit 이 설치돼 있다. 먼저 `ctfkit start chall` 을 실행하라. 플래그가 나오지 않으면 "
         "만들어진 작업 폴더의 AGENTS.md 를 먼저 읽고 이어가라. 명령 목록은 `ctfkit guide`.",
}


def prompt(condition: str, prefix: str = "DH") -> str:
    return COMMON.format(prefix=prefix, extra=EXTRA[condition])


PROMPTS = {c: prompt(c) for c in EXTRA}


# ---------------------------------------------------------------- 모의 문제

def _next_prime(x: int) -> int:
    x |= 1
    while not rsautil.is_probable_prime(x):
        x += 2
    return x


def _png_with_text(text: str) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 4, 4, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + bytes([200, 40, 40] * 4) for _ in range(4))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"tEXt", b"Comment\x00" + text.encode())
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def build_rsa_src(chall: Path, rng: random.Random) -> str:
    """서버 소스 + 출력 파일. 두 번째 소수를 첫 소수 바로 다음 소수로 만든 실수 (페르마)."""
    flag = "DH{fermat_from_source_and_output}"
    p = _next_prime(rng.getrandbits(512) | (1 << 511))
    q = _next_prime(p + rng.getrandbits(16))
    n, e = p * q, 65537
    c = pow(int.from_bytes(flag.encode(), "big"), e, n)
    (chall / "chal.py").write_text(
        "from Crypto.Util.number import getPrime, bytes_to_long\nfrom gmpy2 import next_prime\n\n"
        "p = getPrime(512)\nq = next_prime(p + getPrime(16))\nn = p * q\ne = 65537\n"
        "m = bytes_to_long(open('flag.txt', 'rb').read())\n"
        "print(f'n = {n}')\nprint(f'e = {e}')\nprint(f'c = {pow(m, e, n)}')\n", encoding="ascii")
    (chall / "output.txt").write_text(f"n = {n}\ne = {e}\nc = {c}\n", encoding="ascii")
    return flag


def build_hex_png(chall: Path, rng: random.Random) -> str:
    """이미지의 바이트마다 +128 하고 hex 로 적은 파일 (실전 기록 2 의 형태). 플래그는 PNG 의 tEXt 에 있다."""
    flag = "DH{shifted_png_text_chunk}"
    data = _png_with_text(flag)
    encoded = bytes((b + 128) % 256 for b in data).hex()
    (chall / "encode.py").write_text(
        "data = open('flag.png', 'rb').read()\n"
        "out = bytes((b + 128) % 256 for b in data).hex()\n"
        "open('encoded.txt', 'w').write(out)\n", encoding="ascii")
    (chall / "encoded.txt").write_text(encoded, encoding="ascii")
    return flag


ENGLISH = (
    "the history of cryptography begins thousands of years ago and until recent decades it has been the story of "
    "what might be called classical cryptography that is methods of encryption that use pen and paper or perhaps "
    "simple mechanical aids in the early twentieth century the invention of complex mechanical and "
    "electromechanical machines provided more sophisticated and efficient means of encryption"
)


def build_layers(chall: Path, rng: random.Random) -> str:
    """순서를 알려 주지 않은 다섯 겹 인코딩 (rot13 → base64 → hex → base32 → base64)."""
    import base64
    import codecs

    flag = "DH{five_layers_no_hints}"
    data = codecs.encode(flag, "rot13").encode()
    data = base64.b64encode(data)
    data = data.hex().encode()
    data = base64.b32encode(data)
    data = base64.b64encode(data)
    (chall / "message.txt").write_bytes(data + b"\n")
    return flag


def build_vigenere(chall: Path, rng: random.Random) -> str:
    """키를 모르는 비즈네르. 영어 문단 끝에 플래그가 있다 (글자만 바뀌고 기호는 그대로)."""
    flag = "DH{vigenere_without_key}"
    key = "orbit"
    out, i = [], 0
    for ch in f"{ENGLISH} the flag is {flag}":
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + ord(key[i % len(key)]) - ord("a")) % 26 + base))
            i += 1
        else:
            out.append(ch)
    (chall / "cipher.txt").write_text("".join(out) + "\n", encoding="ascii")
    return flag


def build_xor_key(chall: Path, rng: random.Random) -> str:
    """반복 키 XOR (키 3바이트). 평문은 영어 문단 + 플래그. 바이너리 파일 하나만 준다."""
    flag = "DH{repeating_key_xor}"
    key = b"k3y"
    plain = f"{ENGLISH}. flag: {flag}\n".encode()
    (chall / "secret.bin").write_bytes(bytes(b ^ key[i % len(key)] for i, b in enumerate(plain)))
    return flag


def build_rsa_small_e(chall: Path, rng: random.Random) -> str:
    """e = 3, 패딩 없음. 평문이 작아 c 의 세제곱근이 바로 평문이다."""
    flag = "DH{cube_root_no_padding}"
    p = _next_prime(rng.getrandbits(1024) | (1 << 1023))
    q = _next_prime(rng.getrandbits(1024) | (1 << 1023))
    n = p * q
    c = pow(int.from_bytes(flag.encode(), "big"), 3, n)
    (chall / "encrypt.py").write_text(
        "from Crypto.Util.number import getPrime, bytes_to_long\n\n"
        "p, q = getPrime(1024), getPrime(1024)\nn = p * q\ne = 3\n"
        "m = bytes_to_long(open('flag.txt', 'rb').read())\n"
        "print(f'n = {n}')\nprint(f'c = {pow(m, e, n)}')\n", encoding="ascii")
    (chall / "output.txt").write_text(f"n = {n}\nc = {c}\n", encoding="ascii")
    return flag


def build_rsa_shared(chall: Path, rng: random.Random) -> str:
    """두 공개키가 소수 하나를 같이 쓴다 (난수 생성기 실수). 두 번째 키의 암호문은 주지 않는다."""
    flag = "DH{shared_prime_gcd}"
    p = _next_prime(rng.getrandbits(512) | (1 << 511))
    q1 = _next_prime(rng.getrandbits(512) | (1 << 511))
    q2 = _next_prime(rng.getrandbits(512) | (1 << 511))
    n1, n2, e = p * q1, p * q2, 65537
    c1 = pow(int.from_bytes(flag.encode(), "big"), e, n1)
    (chall / "keygen.py").write_text(
        "from Crypto.Util.number import getPrime, bytes_to_long\n\n"
        "p = getPrime(512)   # cached for speed\n"
        "n1 = p * getPrime(512)\nn2 = p * getPrime(512)\ne = 65537\n"
        "m = bytes_to_long(open('flag.txt', 'rb').read())\n"
        "print(f'n1 = {n1}')\nprint(f'n2 = {n2}')\nprint(f'e = {e}')\nprint(f'c1 = {pow(m, e, n1)}')\n",
        encoding="ascii")
    (chall / "output.txt").write_text(f"n1 = {n1}\nn2 = {n2}\ne = {e}\nc1 = {c1}\n", encoding="ascii")
    return flag


def build_png_zip(chall: Path, rng: random.Random) -> str:
    """PNG 뒤에 ZIP 을 붙이고, ZIP 안 메모는 Base64. 문자열 검색으로는 보이지 않는다."""
    import base64
    import io
    import zipfile

    flag = "DH{zip_after_png_base64}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("memo.txt", base64.b64encode(flag.encode()).decode() + "\n")
        z.writestr("readme.txt", "nothing to see here\n" * 20)
    (chall / "cat.png").write_bytes(_png_with_text("just a cat") + buf.getvalue())
    return flag


def build_nested(chall: Path, rng: random.Random) -> str:
    """zip 안의 tar.gz 안에 hex → base64 로 두 번 인코딩한 메모, 그리고 미끼 파일들."""
    import base64
    import io
    import tarfile
    import zipfile

    flag = "DH{nested_archives_two_encodings}"
    memo = base64.b64encode(flag.encode().hex().encode())
    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w:gz") as t:
        for name, content in (("data/secret/memo.txt", memo + b"\n"), ("data/log.txt", b"boot ok\n" * 50),
                              ("data/fake_flag.txt", b"flag{this_is_not_it}\n")):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            t.addfile(info, io.BytesIO(content))
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("inner.tar.gz", tbuf.getvalue())
        z.writestr("readme.txt", "find the flag\n")
    (chall / "files.zip").write_bytes(zbuf.getvalue())
    return flag


def build_decoys(chall: Path, rng: random.Random) -> str:
    """파일 8개 중 하나의 끝에만 base32 로 적은 플래그가 있다. 나머지는 미끼 (가짜 플래그 형식 포함)."""
    import base64

    flag = "DH{needle_among_decoys}"
    for i in range(8):
        body = rng.randbytes(3000)
        if i == 2:
            body += b"\n" + b"FLAG FORMAT: flag{...}\n"
        if i == 5:
            body += b"\nnote: " + base64.b32encode(flag.encode()) + b"\n"
        (chall / f"dump_{i}.bin").write_bytes(body)
    return flag


PROBLEMS = {
    "rsa-src": ("RSA 소스 + 출력 파일 (가까운 소수)", build_rsa_src),
    "hex-png": ("바이트 +128 한 hex 이미지 (tEXt 안의 플래그)", build_hex_png),
    "layers": ("순서를 모르는 다섯 겹 인코딩", build_layers),
    "vigenere": ("키를 모르는 비즈네르 (영어 문단)", build_vigenere),
    "xor-key": ("반복 키 XOR, 키 길이 모름", build_xor_key),
    "rsa-small-e": ("RSA e = 3, 패딩 없음 (소스 + 출력)", build_rsa_small_e),
    "rsa-shared": ("두 공개키가 소수를 공유 (소스 + 출력)", build_rsa_shared),
    "png-zip": ("PNG 뒤 ZIP 안의 Base64 메모", build_png_zip),
    "nested": ("중첩 압축 + 두 번 인코딩 + 미끼", build_nested),
    "decoys": ("파일 8개 중 하나에만 base32 플래그", build_decoys),
}


# ---------------------------------------------------------------- 실제 문제 (--real)

class RealProblem:
    """git 이 무시하는 폴더의 실제 문제 하나. 정답 파일은 문제 폴더로 복사하지 않는다."""

    def __init__(self, source: Path, flag_file: Path, note: str = "", server: "dict | None" = None):
        self.source, self.flag_file, self.note, self.server = source, flag_file, note, server
        self.id = "real-" + hashlib.sha256(source.stem.encode()).hexdigest()[:6]

    @property
    def title(self) -> str:
        return f"실제 문제 {self.id[5:]}" + (f" ({self.note})" if self.note else "")

    def flag(self) -> str:
        return self.flag_file.read_text(encoding="utf-8").strip()

    def build(self, chall: Path, rng=None) -> str:
        if self.source.is_dir():
            for path in self.source.rglob("*"):
                if not path.is_file() or path in (self.flag_file, self.source / "note.txt"):
                    continue
                target = chall / path.relative_to(self.source)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
        else:
            _extract(self.source, chall)
        return self.flag()


def _extract(zip_path: Path, dest: Path) -> None:
    """압축 해제. 받은 파일이라 폴더 밖으로 나가는 경로(../, 절대 경로)가 있으면 풀지 않는다."""
    root = dest.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            target = (dest / info.filename).resolve()
            if root != target and root not in target.parents:
                raise SystemExit(f"압축 안에 폴더 밖 경로가 있습니다: {info.filename}")
        zf.extractall(dest)


# ---------------------------------------------------------------- 원격 서버 문제 (WSL + socat)

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def parse_server(path: Path) -> dict:
    """`<이름>.server` 사이드카를 읽는다. `key: value` 줄. 최소: bin(압축 안의 실행 파일 경로). 선택: flag(서버 폴더에 둘 플래그 파일 이름, 기본 flag)."""
    spec = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if ":" in line and not line.strip().startswith("#"):
            key, _, value = line.partition(":")
            spec[key.strip()] = value.strip()
    if "bin" not in spec:
        raise SystemExit(f"{path.name}: bin: 줄이 필요합니다 (서버로 띄울 실행 파일)")
    return spec


class Server:
    """리눅스 ELF 문제를 WSL 의 socat 으로 TCP 에 띄운다. 에이전트는 Windows 에서 127.0.0.1 로 접속한다.
    정답(플래그)은 WSL 쪽 서버 폴더에만 두므로 에이전트의 작업 폴더에서는 읽을 수 없다 (풀어야 얻는다)."""

    def __init__(self, spec: dict, flag: str):
        self.spec, self.flag = spec, flag
        self.port = None
        self.tag = None
        self.proc = None

    def _wslpath(self, win: Path) -> str:
        """Windows 경로를 WSL 경로(/mnt/<드라이브>/...)로. wslpath 는 인자의 백슬래시가 먹혀 직접 바꾼다."""
        p = win.resolve()
        drive = p.drive.rstrip(":").lower()
        return f"/mnt/{drive}{p.as_posix()[len(p.drive):]}"

    def start(self, chall: Path) -> int:
        binsrc = chall / self.spec["bin"]
        if not binsrc.is_file():
            raise SystemExit(f"서버 바이너리가 없습니다: {self.spec['bin']}")
        self.port = _free_port()
        self.tag = f"ctfkit-srv-{self.port}"
        serve = f"/tmp/{self.tag}"
        flag_name = self.spec.get("flag", "flag")
        wsl_bin = self._wslpath(binsrc)
        script = (
            f"set -e; rm -rf {serve}; mkdir -p {serve}; "
            f"cp {shlex.quote(wsl_bin)} {serve}/chall; chmod +x {serve}/chall; "
            f"printf '%s\\n' {shlex.quote(self.flag)} > {serve}/{shlex.quote(flag_name)}; "
            f"cd {serve}; exec socat TCP-LISTEN:{self.port},reuseaddr,fork EXEC:./chall"
        )
        self.proc = subprocess.Popen(["wsl.exe", "-u", "root", "--", "bash", "-lc", script],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.5).close()
                return self.port
            except OSError:
                time.sleep(0.1)
        raise SystemExit(f"서버가 뜨지 않았습니다 (port {self.port}). WSL 에 socat 이 있는지 확인하세요.")

    def stop(self) -> None:
        if self.tag:
            subprocess.run(["wsl.exe", "-u", "root", "--", "pkill", "-f", self.tag],
                           capture_output=True)
            subprocess.run(["wsl.exe", "-u", "root", "--", "rm", "-rf", f"/tmp/{self.tag}"],
                           capture_output=True)
        if self.proc:
            self.proc.terminate()


def load_real(folder: Path) -> tuple[dict, list[str]]:
    """({id: RealProblem}, 건너뛴 이유 목록)."""
    if not folder.is_dir():
        raise SystemExit(f"실제 문제 폴더가 없습니다: {folder}")
    found, skipped = {}, []
    for item in sorted(folder.iterdir()):
        if item.suffix == ".zip":
            flag_file, note_file = item.with_suffix(".flag"), item.with_suffix(".note")
        elif item.is_dir():
            flag_file, note_file = item / "flag.txt", item / "note.txt"
        else:
            continue
        if not flag_file.is_file() or not flag_file.read_text(encoding="utf-8").strip():
            skipped.append(f"{item.name}: 정답 파일 없음 ({flag_file.name})")
            continue
        note = note_file.read_text(encoding="utf-8").strip().splitlines()[0] if note_file.is_file() else ""
        server_file = item.with_suffix(".server") if item.suffix == ".zip" else item / "server.txt"
        server = parse_server(server_file) if server_file.is_file() else None
        problem = RealProblem(item, flag_file, note, server)
        found[problem.id] = problem
    return found, skipped


def strip_real(row: dict, flag: str) -> dict:
    """실제 문제 기록에서 내용을 지운다. 도구 이름과 ctfkit 사용 여부만 남겨 load_rows 의 판정이 그대로 되게 한다.
    정답 파일 쪽을 건드린 실행은 무효로 한다."""
    row = dict(row)
    leaked = any("bench/real" in c.replace("\\", "/") or ".flag" in c for c in row["commands"])
    row["commands"] = [c.split(":")[0] + (": ctfkit" if uses_ctfkit([c]) else "") for c in row["commands"]]
    row["error"] = "정답 파일 접근" if leaked else row.get("error", "").replace(flag, "<플래그>")
    if leaked:
        row["valid"] = False
    return row


# ---------------------------------------------------------------- 평가용 규칙 (--eval)

def git_state() -> tuple[str, bool]:
    """(짧은 커밋, 커밋하지 않은 변경이 있는가). git 이 무시하는 파일(bench/real 등)은 세지 않는다."""
    def git(*args):
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    return git("rev-parse", "--short", "HEAD") or "?", bool(git("status", "--porcelain"))


def already_evaluated(rows: list[dict], problems) -> list[str]:
    """평가용으로 이미 잰 문제. 평가용은 한 번만 잰다 (다시 재면 그 사이 고친 것이 섞인다)."""
    seen = {r["problem"] for r in rows if r.get("set") == "eval"}
    return [p for p in problems if p in seen]


def move_candidates(rows: list[dict]) -> list[str]:
    """평가에서 ctfkit 이 도움이 안 된 문제 (B 가 틀렸거나 B 비용 중앙값이 A 이상). 개발용으로 옮겨 분석할 후보다."""
    out = []
    for problem in dict.fromkeys(r["problem"] for r in rows):
        cost = {c: _median([r["cost_usd"] for r in rows if r["problem"] == problem and r["condition"] == c and r["valid"]])
                for c in "AB"}
        wrong = any(not r["solved"] for r in rows if r["problem"] == problem and r["condition"] == "B" and r["valid"])
        if wrong or (cost["A"] is not None and cost["B"] is not None and cost["B"] >= cost["A"]):
            out.append(problem)
    return out


# ---------------------------------------------------------------- 실행

def _plain_venv(base: Path) -> Path:
    """ctfkit 이 없는 가상환경 (조건 A). 시스템 site-packages 를 보지 않으므로 python -m ctfkit 도 안 된다."""
    target = base / "venv-plain"
    if not target.exists():
        venv.EnvBuilder(with_pip=False, system_site_packages=False).create(target)
    return target / ("Scripts" if os.name == "nt" else "bin")


def _env(condition: str, base: Path) -> dict:
    env = dict(os.environ, PYTHONIOENCODING="utf-8", CTFKIT_CONFIG="none")
    if condition == "A":
        scripts = _plain_venv(base)
        # ctfkit 실행 파일이 있는 폴더를 PATH 에서 뺀다
        found = shutil.which("ctfkit")
        drop = {os.path.normcase(os.path.dirname(found))} if found else set()
        parts = [p for p in env.get("PATH", "").split(os.pathsep) if os.path.normcase(p) not in drop]
        env["PATH"] = os.pathsep.join([str(scripts)] + parts)
    return env


def _claude() -> str:
    """claude 실행 파일. Claude Code 가 스스로 업데이트하는 동안 잠깐 사라질 수 있어 몇 번 기다렸다 다시 찾는다
    (60회 측정 중 12번째에 실제로 그랬다)."""
    for _ in range(12):
        exe = shutil.which("claude")
        if exe:
            return exe
        time.sleep(10)
    raise SystemExit("claude 실행 파일을 찾을 수 없습니다 (Claude Code CLI 필요)")


def run_once(problem: str, condition: str, model: str, budget: float, base: Path, seed: int, timeout: int,
             real: "RealProblem | None" = None) -> dict:
    work = Path(tempfile.mkdtemp(prefix=f"{problem}-{condition}-", dir=base))
    chall = work / "chall"
    chall.mkdir()
    flag = real.build(chall) if real else PROBLEMS[problem][1](chall, random.Random(seed))
    prefix = flag.split("{")[0] if "{" in flag else "DH"
    server = Server(real.server, flag) if real and real.server else None
    if server:
        port = server.start(chall)
        (chall / "README.txt").write_text(
            f"이 문제는 원격 서버에 접속해서 푼다. 접속: nc 127.0.0.1 {port}\n", encoding="utf-8")
    log_path = work / "stream.jsonl"
    cmd = [_claude(), "-p", prompt(condition, prefix), "--model", model, "--output-format", "stream-json", "--verbose",
           "--max-budget-usd", str(budget), "--strict-mcp-config", "--no-session-persistence",
           "--tools", "Bash,Read,Write,Edit,Glob,Grep", "--allowedTools", "Bash,Read,Write,Edit,Glob,Grep"]
    start = time.time()
    try:
        proc = subprocess.run(cmd, cwd=work, env=_env(condition, base), capture_output=True, timeout=timeout,
                              encoding="utf-8", errors="replace")
        stdout, stderr, timed_out = proc.stdout, proc.stderr, False
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr, timed_out = "", True
    finally:
        if server:
            server.stop()
    log_path.write_text(stdout, encoding="utf-8")
    print(f"    기록: {log_path}", flush=True)
    row = redact(parse(stdout, problem, condition, model, flag, time.time() - start, timed_out, stderr, str(work)))
    if real:
        row = strip_real(row, flag)
        row["title"] = real.title
    return row


# 저장소에 올리는 기록에 실행한 사람의 폴더 경로(사용자 이름)가 남지 않게 한다
_LOCAL_PATH = re.compile(r"(?:[A-Za-z]:[\\/]|/(?:c|tmp)/)\S*?(?=chall|venv-|[\s'\"]|$)")


def redact(row: dict) -> dict:
    row = dict(row)
    row.pop("work", None)
    row["commands"] = [_LOCAL_PATH.sub("<작업 폴더>/", c) for c in row.get("commands", [])]
    row["error"] = _LOCAL_PATH.sub("<작업 폴더>/", row.get("error", ""))
    return row


def parse(stdout: str, problem, condition, model, flag, wall, timed_out, stderr, work) -> dict:
    result, commands = None, []
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("type") == "result":
            result = event
        elif event.get("type") == "assistant":
            for item in event.get("message", {}).get("content", []):
                if item.get("type") == "tool_use":
                    tool_input = item.get("input", {})
                    commands.append(f"{item.get('name')}: {tool_input.get('command') or tool_input.get('file_path') or ''}"[:200])
    usage = (result or {}).get("usage", {})
    answer = (result or {}).get("result", "") or ""
    used_ctfkit = uses_ctfkit(commands)
    row = {
        "version": __version__, "problem": problem, "condition": condition, "model": model,
        "solved": flag in answer.splitlines()[-1] if answer.strip() else False,
        "flag_anywhere": flag in answer,
        "input": usage.get("input_tokens", 0), "cache_write": usage.get("cache_creation_input_tokens", 0),
        "cache_read": usage.get("cache_read_input_tokens", 0), "output": usage.get("output_tokens", 0),
        "cost_usd": (result or {}).get("total_cost_usd"), "turns": (result or {}).get("num_turns"),
        "duration_s": round(((result or {}).get("duration_ms") or wall * 1000) / 1000, 1),
        "tool_calls": len(commands), "used_ctfkit": used_ctfkit,
        "valid": result is not None and not timed_out and not (condition == "A" and used_ctfkit),
        "error": "timeout" if timed_out else ("" if result else (stderr or "결과 없음")[:300]),
        "commands": commands, "work": work, "time": time.strftime("%Y-%m-%d %H:%M"),
    }
    row["total_tokens"] = row["input"] + row["cache_write"] + row["cache_read"] + row["output"]
    # 비용이 쓰인 곳 (분류 이름과 USD 만. 명령 내용은 남기지 않는다). 실행 폴더는 지워지므로 여기서 계산해 둔다
    parts = {}
    for name, usd in cost_breakdown(stdout).items():
        parts[coarse(name)] = parts.get(coarse(name), 0) + usd
    row["cost_parts"] = {name: round(usd, 6) for name, usd in parts.items()}
    return row


_CTFKIT_CALL = re.compile(r"(?<![\w/.-])(?:ctfkit|-m\s+ctfkit|import\s+ctfkit)(?![\w/.-])")


def uses_ctfkit(commands: list[str]) -> bool:
    """셸 명령에서 ctfkit 을 실행했는가. 경로 안의 글자(venv-no-ctfkit 등)는 세지 않는다."""
    return any(_CTFKIT_CALL.search(c) for c in commands if c.startswith("Bash"))


# ---------------------------------------------------------------- 보고서

def _median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def _change(a, b) -> str:
    if not a or b is None:
        return ""
    return f"{(b - a) / a * 100:+.0f}%"


def render(rows: list[dict]) -> str:
    lines = [
        "# 에이전트 벤치마크 결과",
        "",
        "- 실제 Claude Code(`claude -p`)로 같은 모의 문제를 ctfkit 없이(A) / 있게(B) 풀게 해서 잰 값이다. "
        "측정 방법과 한계는 [README.md](README.md) 의 \"에이전트 벤치마크\" 절 참고.",
        "- 칸은 `A → B` 이고, 반복했으면 중앙값이다. 유효한 실행(시간 초과·ctfkit 사용 위반이 아닌 것)만 센다.",
        "- 토큰 합계 = 입력 + 캐시 쓰기 + 캐시 읽기 + 출력. 캐시 읽기는 싸므로 비용(USD)을 함께 본다.",
        "- 이 파일은 `python bench/agent.py --write` 가 만든다. 직접 고치지 않는다.",
    ]
    rounds = list(dict.fromkeys(r.get("round", FIRST_ROUND) for r in rows))
    summary, sections = [], []
    for name in rounds:
        part = [r for r in rows if r.get("round", FIRST_ROUND) == name]
        table, total = _table(part)
        sections += ["", f"## {name}", ""] + table + _parts_table(part)
        summary.append((name, total, len({r["problem"] for r in part})))
    if len(rounds) > 1:
        lines += ["", "## 회차별 요약", "", "| 회차 | 문제 수 | 비용 합계 A → B (USD, 중앙값의 합) | 변화 |",
                  "| --- | --- | --- | --- |"]
        lines += [f"| {name} | {count} | {t['A']:.3f} → {t['B']:.3f} | {_change(t['A'], t['B'])} |"
                  for name, t, count in summary]
    lines += sections
    invalid = [r for r in rows if not r["valid"]]
    if invalid:
        lines += ["", "무효로 뺀 실행:"] + [f"- {r['problem']} {r['condition']} ({r['time']}): "
                                            f"{'ctfkit 사용' if r['used_ctfkit'] else r['error']}" for r in invalid]
    return "\n".join(lines) + "\n"


def _table(rows: list[dict]):
    lines = ["| 문제 | 모델 | 실행 수 | 정답 | 비용(USD) | 변화 | 출력 토큰 | 토큰 합계 | 왕복 | 시간(초) |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    keys = sorted({(r["problem"], r["model"]) for r in rows})
    titles = {r["problem"]: r["title"] for r in rows if r.get("title")}
    total = {"A": 0.0, "B": 0.0}
    for problem, model in keys:
        cell = {}
        for cond in ("A", "B"):
            runs = [r for r in rows if r["problem"] == problem and r["model"] == model and r["condition"] == cond and r["valid"]]
            cell[cond] = {
                "n": len(runs), "ok": sum(r["solved"] for r in runs),
                "cost": _median([r["cost_usd"] for r in runs]), "out": _median([r["output"] for r in runs]),
                "tok": _median([r["total_tokens"] for r in runs]), "turns": _median([r["turns"] for r in runs]),
                "time": _median([r["duration_s"] for r in runs]),
            }
        a, b = cell["A"], cell["B"]
        if a["cost"] is not None and b["cost"] is not None:
            total["A"] += a["cost"]
            total["B"] += b["cost"]

        def fmt(v, digits=0):
            return "-" if v is None else (f"{v:.{digits}f}" if digits else f"{v:.0f}")

        lines.append(
            f"| {titles.get(problem) or PROBLEMS.get(problem, (problem,))[0]} | {model} | {a['n']} / {b['n']} | {a['ok']}/{a['n']} → {b['ok']}/{b['n']} "
            f"| {fmt(a['cost'], 3)} → {fmt(b['cost'], 3)} | {_change(a['cost'], b['cost'])} "
            f"| {fmt(a['out'])} → {fmt(b['out'])} | {fmt(a['tok'])} → {fmt(b['tok'])} "
            f"| {fmt(a['turns'])} → {fmt(b['turns'])} | {fmt(a['time'], 1)} → {fmt(b['time'], 1)} |")
    if total["A"]:
        lines += ["", f"비용 합계(중앙값의 합): {total['A']:.3f} → {total['B']:.3f} USD ({_change(total['A'], total['B'])})"]
    return lines, total


def _parts_table(rows: list[dict]) -> list[str]:
    """비용이 쓰인 곳 (A → B, 유효한 실행의 평균). 기록에 cost_parts 가 있는 실행만 (11/26 이후)."""
    cell = {}
    for cond in ("A", "B"):
        runs = [r for r in rows if r["condition"] == cond and r["valid"] and r.get("cost_parts")]
        cell[cond] = (len(runs), {name: sum(r["cost_parts"].get(name, 0) for r in runs) / len(runs) for name in PARTS}
                      if runs else {})
    if not cell["A"][0] and not cell["B"][0]:
        return []
    lines = ["", f"비용이 쓰인 곳 (실행당 평균 USD, 실행 {cell['A'][0]} / {cell['B'][0]}개. 나누는 법: `bench/agent_logs.py`)", "",
             "| 위치 | A | B | 변화 |", "| --- | --- | --- | --- |"]
    for name in PARTS:
        a, b = cell["A"][1].get(name), cell["B"][1].get(name)
        if not a and not b:
            continue
        lines.append(f"| {name} | {'-' if a is None else f'{a:.4f}'} | {'-' if b is None else f'{b:.4f}'} "
                     f"| {_change(a, b) if a and b is not None else '-'} |")
    return lines


FIRST_ROUND = "1차: 플래그 근거 출력 후 (v0.31)"


def load_rows() -> list[dict]:
    if not RESULTS.exists():
        return []
    rows = [json.loads(line) for line in RESULTS.read_text(encoding="utf-8").splitlines() if line.strip()]
    for row in rows:   # 판정 규칙을 고치면 저장된 기록에도 다시 적용한다
        row.setdefault("round", FIRST_ROUND)
        row.setdefault("set", "dev" if row["problem"].startswith("real-") else "mock")
        row["used_ctfkit"] = uses_ctfkit(row["commands"])
        row["valid"] = not row["error"] and not (row["condition"] == "A" and row["used_ctfkit"])
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--problems", help="쉼표로 구분한 문제 id (기본: 전부)")
    parser.add_argument("--real", nargs="?", const=str(REAL_DIR), metavar="DIR",
                        help="모의 문제 대신 실제 문제의 개발용 폴더를 쓴다 (기본 bench/real/dev, git 이 무시하는 폴더)")
    parser.add_argument("--eval", action="store_true",
                        help="평가용 폴더(bench/real/eval)를 쓴다. 커밋한 깨끗한 상태여야 하고, 이미 잰 문제는 다시 재지 않는다")
    parser.add_argument("--again", action="store_true", help="--eval 에서 이미 잰 문제도 다시 잰다 (보고서에 표시됨)")
    parser.add_argument("--conditions", default="A,B")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--model", default="sonnet")
    parser.add_argument("--budget", type=float, default=1.0, help="실행 한 번의 비용 상한 (USD)")
    parser.add_argument("--timeout", type=int, default=900, help="실행 한 번의 시간 상한 (초)")
    parser.add_argument("--workdir", help="문제를 풀 임시 폴더의 위치 (기본: 시스템 임시 폴더)")
    parser.add_argument("--write", action="store_true", help=f"결과를 {RESULTS.name} 에 더하고 {REPORT.name} 를 다시 만든다")
    parser.add_argument("--report", action="store_true", help="실행하지 않고 저장된 결과로 보고서만 다시 만든다")
    parser.add_argument("--list", action="store_true", help="문제 목록")
    parser.add_argument("--round", help="이번 측정의 이름 (보고서에서 회차별로 나눈다. 기본: v<버전>, 평가용은 버전과 커밋)")
    parser.add_argument("--resume", action="store_true",
                        help="같은 --round 로 이미 기록된 (문제, 조건) 의 반복 횟수만큼은 건너뛴다 (중단된 측정 이어서 하기)")
    args = parser.parse_args()

    folder = EVAL_DIR if args.eval else (Path(args.real) if args.real else None)
    kind = "eval" if args.eval else ("dev" if args.real else "mock")
    real, skipped = load_real(folder) if folder else ({}, [])
    catalog = {k: p.title for k, p in real.items()} if folder else {k: t for k, (t, _) in PROBLEMS.items()}
    commit, dirty = git_state()
    if args.list:
        for key, title in catalog.items():
            print(f"{key:12} {title}")
        for line in skipped:
            print(f"건너뜀  {line}")
        return 0
    if args.report:
        REPORT.write_text(render(load_rows()), encoding="utf-8")
        print(REPORT.read_text(encoding="utf-8"))
        return 0

    selected = args.problems.split(",") if args.problems else list(catalog)
    for problem in selected:
        if problem not in catalog:
            raise SystemExit(f"모르는 문제: {problem} (--list 참고)")
    if args.round is None:
        args.round = f"평가: v{__version__} ({commit})" if args.eval else f"v{__version__}"
    if args.eval:
        if dirty:
            raise SystemExit("평가용은 커밋한 깨끗한 상태에서만 잰다 (git status 에 변경이 있음). 고친 것을 먼저 커밋하세요.")
        again = already_evaluated(load_rows(), selected)
        if again and not args.again and not args.resume:
            raise SystemExit(f"평가용으로 이미 잰 문제: {', '.join(again)}. 평가용은 한 번만 잰다 "
                             "(실패한 문제는 bench/real/dev 로 옮겨 분석). 그래도 다시 재려면 --again")

    base = Path(args.workdir or tempfile.mkdtemp(prefix="ctfkit-agent-"))
    base.mkdir(parents=True, exist_ok=True)
    new = []
    done = [r for r in load_rows() if r["round"] == args.round] if args.resume else []
    for line in skipped:
        print(f"건너뜀  {line}")
    for problem in selected:
        for k in range(args.repeat):
            for cond in args.conditions.split(","):
                if args.resume and k < sum(1 for r in done if r["problem"] == problem and r["condition"] == cond):
                    continue
                print(f"[{time.strftime('%H:%M:%S')}] {problem} 조건 {cond} #{k + 1} ...", flush=True)
                row = run_once(problem, cond, args.model, args.budget, base, seed=2026 + k, timeout=args.timeout,
                               real=real.get(problem))
                print(f"    정답 {row['solved']}  비용 {row['cost_usd']}  토큰 {row['total_tokens']}  왕복 {row['turns']}  "
                      f"{row['duration_s']}초  ctfkit 사용 {row['used_ctfkit']}  유효 {row['valid']} {row['error']}", flush=True)
                row["round"] = args.round
                row["set"], row["commit"] = kind, commit + ("+변경" if dirty else "")
                if args.eval and args.again:
                    row["again"] = True
                new.append(row)
                if args.write:
                    with RESULTS.open("a", encoding="utf-8") as f:
                        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    rows = load_rows() if args.write else new
    report = render(rows)
    if args.write:
        REPORT.write_text(report, encoding="utf-8")
    print(report)
    if args.eval:
        move = move_candidates(new)
        if move:
            print("ctfkit 이 도움이 안 된 평가용 문제 (개발용으로 옮겨 분석할 후보): " + ", ".join(
                f"{p} ({catalog[p]})" for p in move))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
