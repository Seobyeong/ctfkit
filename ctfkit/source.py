"""문제와 함께 받은 소스 코드에서 "무엇을 쓰는 문제인가" 단서를 뽑는다.

암호·웹·pwn 문제는 보통 challenge.py, app.py, chall.c 같은 소스를 준다. 플래그는 서버에 있으므로 파일을 아무리
뒤져도 나오지 않고, 할 일은 소스를 읽는 것이다. 여기서는 읽기 전에 한눈에 볼 수 있는 사실만 정규식으로 모은다:
어떤 라이브러리·함수를 쓰는지, 입력을 받는지(nc 로 접속하는 문제인지), 위험한 함수가 있는지.

공격 방법을 추측하지는 않는다. 사실만 보여 주고, 그 분야에 맞는 ctfkit 명령을 다음 단계로 제안한다.
"""

import os
import re
from dataclasses import dataclass, field

_EXT = {
    ".py": "Python", ".sage": "SageMath", ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++",
    ".js": "JavaScript", ".ts": "TypeScript", ".php": "PHP", ".java": "Java", ".go": "Go",
    ".rs": "Rust", ".rb": "Ruby", ".sol": "Solidity", ".sh": "셸 스크립트",
}

# 확장자가 없을 때 내용으로 판별한다 (드림핵은 파일 이름을 바꿔 주는 경우가 있다)
_CONTENT_LANG = [
    (re.compile(r"\A#!.*python"), "Python"),
    (re.compile(r"\A#!.*(?:ba)?sh\b"), "셸 스크립트"),
    (re.compile(r"<\?php"), "PHP"),
    (re.compile(r"^\s*#include\s*[<\"]", re.M), "C"),
    (re.compile(r"^\s*(?:from\s+[\w.]+\s+)?import\s+\w+", re.M), "Python"),
]

_F = re.IGNORECASE


@dataclass
class SourceInfo:
    lang: str
    clues: list = field(default_factory=list)   # 사실 단서 ("RSA", "입력을 받음" ...)
    tips: list = field(default_factory=list)    # 다음에 해 볼 ctfkit 명령 (앞에 "ctfkit " 을 붙이지 않은 형태)
    remote: bool = False                        # 입력을 받는다 = nc 로 접속해 주고받는 문제일 가능성
    memory: bool = False                        # C 계열에서 메모리를 넘칠 수 있는 입력(gets·strcpy·read(0,…) 등)이 보인다

    def clue(self, text: str) -> None:
        if text not in self.clues:
            self.clues.append(text)

    def tip(self, text: str) -> None:
        if text not in self.tips:
            self.tips.append(text)


def language(text: str, filename: str = "") -> str | None:
    """소스 코드면 언어 이름, 아니면 None."""
    ext = os.path.splitext(filename)[1].lower()
    if ext in _EXT:
        return _EXT[ext]
    for pattern, lang in _CONTENT_LANG:
        if pattern.search(text):
            return lang
    return None


def _found(pattern: str, text: str, flags=0) -> list[str]:
    """pattern 에 걸린 첫 그룹(없으면 전체)을 순서대로, 중복 없이."""
    out = []
    for m in re.finditer(pattern, text, flags):
        value = m.group(1) if m.groups() else m.group(0)
        if value and value not in out:
            out.append(value)
    return out


def analyze(text: str, filename: str = "") -> SourceInfo | None:
    lang = language(text, filename)
    if lang is None:
        return None
    info = SourceInfo(lang)

    # ---- 암호
    if re.search(r"getStrongPrime|getPrime|bytes_to_long|long_to_bytes|\bRSA\b|\bnext_prime\(", text):
        info.clue("RSA·정수 암호")
        for bits in _found(r"get(?:Strong)?Prime\(\s*(\d+)", text):
            info.clue(f"소수 {bits}비트")
        for value in _found(r"(?<![\w])(?:self\.)?e\s*=\s*(0x[0-9a-fA-F]+|\d+)\b", text)[:2]:
            info.clue(f"e={value}")
        info.tip("rsa decrypt -n N -e E -c C [-p P -q Q]")
        info.tip("template rsa -n N -e E -c C")
    if re.search(r"\b(?:AES|DES3?|Blowfish|ARC4|ChaCha20)\.new\(|\bCipher\(", text):
        info.clue("블록·스트림 암호 " + "·".join(_found(r"\b(AES|DES3?|Blowfish|ARC4|ChaCha20)\.new\(", text)))
        made = len(re.findall(r"\b(?:AES|DES3?|Blowfish|ARC4|ChaCha20)\.new\(", text))
        if made > 1:
            info.clue(f"암호 객체 {made}개")
        modes = _found(r"MODE_(\w+)", text)
        if modes:
            info.clue("모드 " + "·".join(modes))
        if "CBC" in modes:
            info.tip("crypto cbc-flip --cipher B64 --offset N --known A --desired B")
    if re.search(r"\bunpad\(|\bpad\(", text):
        info.clue("패딩 처리")
    if re.search(r"random\.(?:seed|getrandbits|randint|randrange|random)\b|\bmt19937\b|\bsrand\(", text):
        info.clue("의사 난수 (random·srand)")
    hashes = _found(r"hashlib\.(md5|sha1|sha224|sha256|sha384|sha512|sha3_\w+|blake2\w)", text)
    if hashes:
        info.clue("해시 " + "·".join(hashes))
        info.tip("hash crack H -w WORDS")
    if re.search(r"\bstrxor\(|\bxor\(|\^\s*(?:key|k)\b|\b(?:key|k)\s*\^", text):
        info.clue("XOR")
        info.tip("crack xor DATA")
    rot = _found(r"([+-]\s*\d+)\s*\)\s*%\s*(?:256|0x100|len\()", text)
    if rot:
        info.clue("나머지 연산으로 값 회전 " + ", ".join(r.replace(" ", "") for r in rot))
    if re.search(r"\bhex\(|\.hex\(\)|hexlify\(", text):
        info.clue("hex 글자로 변환")
    if re.search(r"\becdsa\b|EllipticCurve|\bECC\b|\bsecp\d+", text, _F):
        info.clue("타원 곡선")

    # ---- 웹
    web = _found(r"\b(Flask|FastAPI|express|Django|Express)\b", text) + (["PHP"] if re.search(r"<\?php", text) else [])
    if web:
        info.clue("웹 서버 " + "·".join(dict.fromkeys(web)))
        routes = _found(r"@\w+\.(?:route|get|post)\(\s*['\"]([^'\"]+)", text) or \
            _found(r"\b(?:app|router)\.(?:get|post|all|use)\(\s*['\"]([^'\"]+)", text)
        if routes:
            info.clue("경로 " + ", ".join(routes[:8]) + (f" 외 {len(routes) - 8}개" if len(routes) > 8 else ""))
        info.tip("template web URL")
    if re.search(r"\b(?:SELECT|INSERT|UPDATE)\b[^\n]*\b(?:FROM|INTO|SET)\b", text) or re.search(r"sqlite3|mysql|\.execute\(", text):
        info.clue("SQL")
    risky_web = _found(r"\b(render_template_string|eval|exec|os\.system|os\.popen|subprocess\.\w+|pickle\.loads|"
                       r"yaml\.load|unserialize|shell_exec|passthru)\s*\(", text)
    if risky_web:
        info.clue("위험 함수 " + ", ".join(risky_web))

    # ---- pwn (C 계열)
    if lang in ("C", "C++"):
        risky = _found(r"\b(gets|strcpy|strcat|sprintf|system|alloca)\s*\(", text)
        if re.search(r"scanf\(\s*\"[^\"]*%s", text):
            risky.append("scanf(%s)")
        if re.search(r"\bprintf\(\s*[A-Za-z_]\w*\s*\)", text):
            risky.append("printf(변수)")
        reads = bool(re.search(r"\bread\(\s*0\s*,", text))
        if reads:
            info.clue("read(0, ...) 로 입력")
        if risky:
            info.clue("위험 함수 " + ", ".join(risky))
        info.tip("template pwn <바이너리>")   # 접속·보호 기법이 채워진 뼈대. 메모리 공격이 아니어도 원격 응답에 쓴다
        # system 은 위험 함수로 보여 주지만 메모리를 넘치게 하지는 않는다 (플래그를 보여 주는 system("cat flag") 가 흔하다)
        if [r for r in risky if r != "system"] or reads:
            # 오버플로 오프셋은 메모리를 넘칠 수 있는 입력이 보일 때만 권한다
            # (실전 기록 6: 산수 문제를 주고받는 C 서버에 pwn cyclic 을 권했다)
            info.tip("pwn cyclic 200")
            info.memory = True

    # ---- 공통: 입력과 플래그 위치
    for size in _found(r"\b(?:urandom|get_random_bytes|token_bytes|randbytes)\(\s*(\d+)\s*\)", text)[:3]:
        info.clue(f"무작위 {size}바이트")
    if re.search(r"\binput\(|sys\.stdin|\bsocket\b|\.recv\(|\bscanf\(|\bgets\(|\bfgets\(|\bread\(\s*0\s*,", text):
        info.clue("입력을 받음 (nc 로 접속하는 문제일 가능성)")
        info.remote = True
    for seconds in _found(r"\balarm\(\s*(\d+)\s*\)", text)[:1]:
        info.clue(f"시간 제한 {seconds}초")
    for name in _found(r"open\(\s*['\"]([^'\"]*flag[^'\"]*)['\"]", text, _F)[:2]:
        info.clue(f"플래그 파일 {name}")
    funcs = _found(r"\bdef\s+(encrypt|decrypt|sign|verify|encode|decode|check\w*)\s*\(", text)
    if funcs:
        info.clue("함수 " + ", ".join(funcs))
    return info
