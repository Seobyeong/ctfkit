"""해결률 벤치마크: 자동 생성한 문제 중 auto 엔진이 플래그까지 푸는 비율을 잰다.

    python bench/solve.py              # 표를 화면에 출력
    python bench/solve.py --write      # bench/SOLVE.md 와 bench/history/solve-v<버전>.md 로 저장
    python bench/solve.py --failures   # 못 푼 문제의 입력을 함께 출력

규칙 (docs/ROADMAP.md 2.1 절):
  - 문제는 ctfkit 코드를 쓰지 않고 만든다. 아래 인코더는 모두 표준 라이브러리로 따로 구현했다.
    ctfkit 의 encode 로 만든 문제를 ctfkit 의 decode 로 풀면 같은 버그가 양쪽에 있어도 통과하기 때문이다.
  - 아직 지원하지 않는 인코딩도 넣는다. 표에 X 로 남아야 무엇이 남았는지 보인다.
  - 플래그는 무작위로 만들되 시드를 고정해, 실행할 때마다 같은 문제가 나온다.
  - 플래그가 없는 입력도 넣는다. 변환을 늘리면 우연히 플래그 모양이 된 쓰레기(오탐)가 나오기 쉬워진다.
    해결률만 보면 이 부작용이 보이지 않는다.
"""

import argparse
import base64
import codecs
import gzip
import math
import os
import platform
import random
import statistics
import sys
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctfkit import __version__  # noqa: E402
from ctfkit.engine import search  # noqa: E402

SEED = 2026
PER_ENCODING = 5      # 한 겹: 인코딩마다 문제 수
TWO_LAYER = 100       # 두 겹 문제 수
THREE_LAYER = 60      # 세 겹 문제 수
NEGATIVES = 12        # 플래그가 없는 입력: 종류마다 개수

# ---------------------------------------------------------------- 인코더 (ctfkit 과 독립)

MORSE = {
    "a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".", "f": "..-.", "g": "--.", "h": "....", "i": "..",
    "j": ".---", "k": "-.-", "l": ".-..", "m": "--", "n": "-.", "o": "---", "p": ".--.", "q": "--.-", "r": ".-.",
    "s": "...", "t": "-", "u": "..-", "v": "...-", "w": ".--", "x": "-..-", "y": "-.--", "z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....",
    "7": "--...", "8": "---..", "9": "----.",
}
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def _radix(data: bytes, alphabet: str) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, len(alphabet))
        out = alphabet[r] + out
    return alphabet[0] * (len(data) - len(data.lstrip(b"\x00"))) + out


def _base45(data: bytes) -> str:
    out = []
    for i in range(0, len(data), 2):
        chunk = data[i:i + 2]
        if len(chunk) == 2:
            n = chunk[0] * 256 + chunk[1]
            out += [B45[n % 45], B45[n // 45 % 45], B45[n // 2025]]
        else:
            out += [B45[chunk[0] % 45], B45[chunk[0] // 45]]
    return "".join(out)


def _shift(text: str, k: int) -> str:
    out = []
    for c in text:
        if c.isascii() and c.isalpha():
            base = 65 if c.isupper() else 97
            out.append(chr((ord(c) - base + k) % 26 + base))
        else:
            out.append(c)
    return "".join(out)


def _affine(text: str, a: int, b: int) -> str:
    out = []
    for c in text:
        if c.isascii() and c.isalpha():
            base = 65 if c.isupper() else 97
            out.append(chr((a * (ord(c) - base) + b) % 26 + base))
        else:
            out.append(c)
    return "".join(out)


def _atbash(text: str) -> str:
    return "".join(chr(155 - ord(c)) if c.isascii() and c.isupper()
                   else chr(219 - ord(c)) if c.isascii() and c.islower() else c for c in text)


def _rot47(text: str) -> str:
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in text)


def _rail(text: str, rails: int) -> str:
    rows = [[] for _ in range(rails)]
    r, d = 0, 1
    for ch in text:
        rows[r].append(ch)
        r += d
        if r in (0, rails - 1):
            d = -d
    return "".join("".join(row) for row in rows)


def _bacon(text: str) -> str:
    letters = [c for c in text.lower() if c.isascii() and c.isalpha()]
    return " ".join(format(ord(c) - 97, "05b").replace("0", "A").replace("1", "B") for c in letters)


def _uu(data: bytes) -> str:
    return codecs.encode(data, "uu").decode("ascii")


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


@dataclass
class Encoder:
    name: str
    fn: Callable                  # (글자, 난수) -> 글자
    stackable: bool = False       # 결과가 글자라 그 위에 다른 인코딩을 또 씌울 수 있는가
    lossy: bool = False           # 대소문자·기호를 잃는가 (정답을 느슨하게 비교한다)
    group: str = "인코딩"


def _b(text: str) -> bytes:
    return text.encode("utf-8")


ENCODERS = [
    # --- 진법·바이트 표기
    Encoder("base64", lambda s, r: base64.b64encode(_b(s)).decode(), stackable=True),
    Encoder("base64 (패딩 없음)", lambda s, r: base64.b64encode(_b(s)).decode().rstrip("=")),
    Encoder("base64 URL-safe", lambda s, r: base64.urlsafe_b64encode(b"\xfb\xef\xbe" + _b(s)).decode()),
    Encoder("base32", lambda s, r: base64.b32encode(_b(s)).decode(), stackable=True),
    Encoder("base32 소문자", lambda s, r: base64.b32encode(_b(s)).decode().lower()),
    Encoder("base58", lambda s, r: _radix(_b(s), B58), stackable=True),
    Encoder("base62", lambda s, r: _radix(_b(s), B62)),
    Encoder("base45", lambda s, r: _base45(_b(s))),
    Encoder("base85", lambda s, r: base64.b85encode(_b(s)).decode()),
    Encoder("ascii85", lambda s, r: base64.a85encode(_b(s)).decode()),
    Encoder("hex", lambda s, r: _b(s).hex(), stackable=True),
    Encoder("hex 공백 구분", lambda s, r: " ".join(f"{x:02x}" for x in _b(s)), stackable=True),
    Encoder("hex 0x 목록", lambda s, r: " ".join(f"0x{x:02x}" for x in _b(s))),
    Encoder("2진수", lambda s, r: " ".join(f"{x:08b}" for x in _b(s)), stackable=True),
    Encoder("2진수 (공백 없음)", lambda s, r: "".join(f"{x:08b}" for x in _b(s))),
    Encoder("10진 코드", lambda s, r: " ".join(str(x) for x in _b(s)), stackable=True),
    Encoder("8진 코드", lambda s, r: " ".join(f"{x:o}" for x in _b(s))),
    # --- 웹·문자열 이스케이프
    Encoder("URL 인코딩", lambda s, r: "".join(f"%{x:02X}" for x in _b(s)), stackable=True),
    Encoder("URL 이중 인코딩", lambda s, r: "".join(f"%25{x:02X}" for x in _b(s))),
    Encoder("HTML 엔티티 (10진)", lambda s, r: "".join(f"&#{x};" for x in _b(s)), stackable=True),
    Encoder("HTML 엔티티 (16진)", lambda s, r: "".join(f"&#x{x:x};" for x in _b(s))),
    Encoder("유니코드 이스케이프", lambda s, r: "".join(f"\\u{x:04x}" for x in _b(s)), stackable=True),
    Encoder("\\x 이스케이프", lambda s, r: "".join(f"\\x{x:02x}" for x in _b(s))),
    Encoder("quoted-printable", lambda s, r: "".join(f"={x:02X}" for x in _b(s))),
    Encoder("uuencode", lambda s, r: _uu(_b(s))),
    # --- 고전 암호·치환
    Encoder("ROT13", lambda s, r: _shift(s, 13), stackable=True, group="암호"),
    Encoder("시저 (키 무작위)", lambda s, r: _shift(s, r.choice([k for k in range(1, 26) if k != 13])), group="암호"),
    Encoder("ROT47", lambda s, r: _rot47(s), group="암호"),
    Encoder("아트배시", lambda s, r: _atbash(s), group="암호"),
    Encoder("아핀 (a=5, b=8)", lambda s, r: _affine(s, 5, 8), group="암호"),
    Encoder("뒤집기", lambda s, r: s[::-1], stackable=True, group="암호"),
    Encoder("레일 펜스 (3)", lambda s, r: _rail(s, 3), group="암호"),
    Encoder("레일 펜스 (4)", lambda s, r: _rail(s, 4), group="암호"),
    Encoder("모스 부호", lambda s, r: " ".join(MORSE[c] for c in s.lower() if c in MORSE), lossy=True, group="암호"),
    Encoder("베이컨 암호", lambda s, r: _bacon(s), lossy=True, group="암호"),
    Encoder("A1Z26", lambda s, r: " ".join(str(ord(c) - 96) for c in s.lower() if "a" <= c <= "z"), lossy=True,
            group="암호"),
    # --- 압축·XOR
    Encoder("gzip + base64", lambda s, r: base64.b64encode(gzip.compress(_b(s), mtime=0)).decode(), group="압축·XOR"),
    Encoder("zlib + hex", lambda s, r: zlib.compress(_b(s)).hex(), group="압축·XOR"),
    Encoder("zlib + base64", lambda s, r: base64.b64encode(zlib.compress(_b(s))).decode(), group="압축·XOR"),
    Encoder("XOR 1바이트 (hex)", lambda s, r: _xor(_b(s), bytes([r.randrange(1, 256)])).hex(), group="압축·XOR"),
    Encoder("XOR 2바이트 키 (hex)", lambda s, r: _xor(_b(s), bytes(r.randrange(1, 256) for _ in range(2))).hex(),
            group="압축·XOR"),
    Encoder("XOR 4바이트 키 (hex)", lambda s, r: _xor(_b(s), bytes(r.randrange(1, 256) for _ in range(4))).hex(),
            group="압축·XOR"),
    Encoder("XOR 1바이트 + base64",
            lambda s, r: base64.b64encode(_xor(_b(s), bytes([r.randrange(1, 256)]))).decode(), group="압축·XOR"),
]


# ---------------------------------------------------------------- 문제 만들기

@dataclass
class Case:
    layers: tuple          # 적용한 인코더 이름 (안쪽부터)
    flag: str
    data: str
    lossy: bool


def make_flag(rng: random.Random) -> str:
    words = ["flag", "easy", "base", "layer", "crypto", "hidden", "simple", "decode", "secret", "warm", "up", "xor",
             "is", "not", "safe", "you", "found", "it", "nice", "try", "hello", "world", "c0de", "h4ck", "r3v"]
    body = "_".join(rng.choice(words) for _ in range(rng.randint(2, 4)))
    return "DH{" + body + "}"


def build_cases() -> list[Case]:
    rng = random.Random(SEED)
    cases = []
    for enc in ENCODERS:
        for _ in range(PER_ENCODING):
            flag = make_flag(rng)
            cases.append(Case((enc.name,), flag, enc.fn(flag, rng), enc.lossy))
    stack = [e for e in ENCODERS if e.stackable]
    for count, depth in ((TWO_LAYER, 2), (THREE_LAYER, 3)):
        for _ in range(count):
            flag = make_flag(rng)
            chosen = [rng.choice(stack) for _ in range(depth)]
            data = flag
            for enc in chosen:
                data = enc.fn(data, rng)
            cases.append(Case(tuple(e.name for e in chosen), flag, data, False))
    return cases


SENTENCES = [
    "the quick brown fox jumps over the lazy dog", "hello world this is a plain message",
    "meet me at the station at nine tonight", "please reset my password before friday",
    "nothing to see here just some ordinary text", "the server will restart in five minutes",
    "remember to bring the documents tomorrow", "this file contains no secrets at all",
    "attack at dawn is a very old example", "lorem ipsum dolor sit amet consectetur",
    "all work and no play makes jack a dull boy", "to be or not to be that is the question",
]


def build_negatives() -> list[tuple[str, str]]:
    """플래그가 들어 있지 않은 입력 [(종류, 데이터)]. auto 가 플래그를 찾았다고 하면 오탐이다."""
    rng = random.Random(SEED + 1)
    symbols = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[];:,.<>/?"
    out = []
    for i in range(NEGATIVES):
        sentence = SENTENCES[i % len(SENTENCES)]
        out.append(("평문 문장", sentence))
        out.append(("문장의 base64", base64.b64encode(sentence.encode()).decode()))
        out.append(("무작위 바이트의 hex", rng.randbytes(rng.randint(16, 40)).hex()))
        out.append(("무작위 바이트의 base64", base64.b64encode(rng.randbytes(rng.randint(16, 40))).decode()))
        out.append(("무작위 기호 글자열", "".join(rng.choice(symbols) for _ in range(rng.randint(20, 40)))))
        out.append(("무작위 숫자 목록", " ".join(str(rng.randrange(256)) for _ in range(rng.randint(8, 24)))))
    return out


def run_negatives(negatives) -> list[dict]:
    rows = []
    for kind, data in negatives:
        start = time.perf_counter()
        try:
            results = search(data.encode("utf-8"))
            flag = results[0].flag if results else None
        except Exception as e:
            flag = None
            print(f"[!] 예외: {kind}: {e!r}", file=sys.stderr)
        rows.append({"kind": kind, "data": data, "flag": flag, "time": time.perf_counter() - start})
    return rows


# ---------------------------------------------------------------- 풀기

def _letters(text: str) -> str:
    return "".join(c for c in text.lower() if c.isalnum())


def solved(case: Case, results) -> bool:
    """맨 위 결과가 정답인가. 기호를 잃는 인코딩(모스 등)은 상위 3개 안에 글자가 맞는 결과가 있으면 정답."""
    if not results:
        return False
    if not case.lossy:
        return results[0].flag is not None and results[0].flag.decode("utf-8", "replace") == case.flag
    want = _letters(case.flag)
    # A1Z26·베이컨은 숫자도 잃는다
    want_alpha = "".join(c for c in want if c.isalpha())
    for result in results[:3]:
        got = _letters(result.data.decode("utf-8", "replace"))
        if want in got or (want_alpha and want_alpha in "".join(c for c in got if c.isalpha())):
            return True
    return False


def run(cases: list[Case]) -> list[dict]:
    rows = []
    for case in cases:
        start = time.perf_counter()
        try:
            results = search(case.data.encode("utf-8"))
            ok = solved(case, results)
        except Exception as e:   # 엔진이 죽는 입력도 "못 풂" 으로 세고 계속 간다
            ok, results = False, []
            print(f"[!] 예외: {case.layers}: {e!r}", file=sys.stderr)
        rows.append({"case": case, "ok": ok, "time": time.perf_counter() - start})
    return rows


# ---------------------------------------------------------------- 결과표

def _rate(rows) -> str:
    n = len(rows)
    k = sum(r["ok"] for r in rows)
    return f"{k}/{n} ({k / n * 100:.0f}%)" if n else "-"


def summary(rows) -> dict:
    by_depth = {d: [r for r in rows if len(r["case"].layers) == d] for d in (1, 2, 3)}
    return {
        "rate": {d: (sum(r["ok"] for r in rs) / len(rs) if rs else 0.0) for d, rs in by_depth.items()},
        "median": statistics.median(r["time"] for r in rows),
        "p95": sorted(r["time"] for r in rows)[math.ceil(len(rows) * 0.95) - 1],
        "total": sum(r["time"] for r in rows),
    }


def render(rows, negatives=()) -> str:
    one = [r for r in rows if len(r["case"].layers) == 1]
    two = [r for r in rows if len(r["case"].layers) == 2]
    three = [r for r in rows if len(r["case"].layers) == 3]
    s = summary(rows)
    lines = [
        "# 해결률 벤치마크 결과",
        "",
        f"- ctfkit {__version__} · Python {platform.python_version()} · {platform.system()}",
        f"- 문제 {len(rows)}개 (한 겹 {len(one)}, 두 겹 {len(two)}, 세 겹 {len(three)}), 시드 {SEED}",
        "- 문제는 ctfkit 코드를 쓰지 않고 표준 라이브러리로 만든다. 맨 위 결과의 플래그가 정확히 같아야 정답이다.",
        "- 이 파일은 `python bench/solve.py --write` 가 만든다. 직접 고치지 않는다.",
        "",
        "## 요약",
        "",
        "| 구분 | 해결률 |",
        "| --- | --- |",
        f"| 한 겹 | {_rate(one)} |",
        f"| 두 겹 | {_rate(two)} |",
        f"| 세 겹 | {_rate(three)} |",
        f"| 전체 | {_rate(rows)} |",
        f"| 오탐 (플래그 없는 입력 {len(negatives)}개 중 플래그를 찾았다고 한 것) | "
        f"{sum(n['flag'] is not None for n in negatives)}개 |",
        "",
        f"문제당 시간: 중앙값 {s['median']:.2f}초, 95% {s['p95']:.2f}초, 전체 {s['total']:.0f}초.",
        "",
        "## 한 겹: 인코딩별",
        "",
        "| 분류 | 인코딩 | 해결 |",
        "| --- | --- | --- |",
    ]
    for enc in ENCODERS:
        mine = [r for r in one if r["case"].layers == (enc.name,)]
        k = sum(r["ok"] for r in mine)
        mark = "O" if k == len(mine) else ("X" if k == 0 else "△")
        lines.append(f"| {enc.group} | {enc.name} | {mark} {k}/{len(mine)} |")
    lines += [
        "",
        "O 는 모두 풂, △ 는 일부만 풂, X 는 하나도 못 풂.",
        "",
        "## 여러 겹: 못 푼 조합에 자주 나온 인코딩",
        "",
        "| 인코딩 | 들어간 문제 | 그중 못 푼 문제 |",
        "| --- | --- | --- |",
    ]
    stacked = two + three
    for enc in [e for e in ENCODERS if e.stackable]:
        mine = [r for r in stacked if enc.name in r["case"].layers]
        bad = sum(not r["ok"] for r in mine)
        lines.append(f"| {enc.name} | {len(mine)} | {bad} |")
    lines += ["", "## 오탐: 플래그가 없는 입력", "", "| 종류 | 입력 수 | 플래그를 찾았다고 한 것 |", "| --- | --- | --- |"]
    for kind in dict.fromkeys(n["kind"] for n in negatives):
        mine = [n for n in negatives if n["kind"] == kind]
        lines.append(f"| {kind} | {len(mine)} | {sum(n['flag'] is not None for n in mine)} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="ctfkit 해결률 벤치마크")
    ap.add_argument("--write", action="store_true", help="bench/SOLVE.md 로 저장")
    ap.add_argument("--failures", action="store_true", help="못 푼 문제의 입력을 출력")
    args = ap.parse_args()
    os.environ["CTFKIT_CONFIG"] = "none"   # 대회 설정 파일이 있어도 같은 조건에서 잰다

    rows = run(build_cases())
    negatives = run_negatives(build_negatives())
    text = render(rows, negatives)
    if args.write:
        (ROOT / "bench" / "SOLVE.md").write_text(text, encoding="utf-8")
        history = ROOT / "bench" / "history"
        history.mkdir(exist_ok=True)
        (history / f"solve-v{__version__}.md").write_text(text, encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(text)
    if args.failures:
        for r in rows:
            if not r["ok"]:
                print(" > ".join(r["case"].layers), "|", r["case"].data[:120])
        for n in negatives:
            if n["flag"] is not None:
                print("오탐:", n["kind"], "|", n["data"][:80], "->", n["flag"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
