"""바이트를 숫자로 적은 표기: 2진수, 10진 코드, 8진 코드, A1Z26.

CTF 에서 "숫자만 잔뜩 있는 문제" 는 대부분 이 넷 중 하나다. 같은 입력이 여러 표기로 읽힐 수 있어서
(예: "104 105" 는 10진으로도 8진으로도 읽힌다) auto 는 가능한 것을 모두 시도하고 점수로 고른다.
"""

import re

from ctfkit.registry import Transform, TransformError, register

_BINARY_RE = re.compile(rb"^[01\s]+$")
_SEP = re.compile(rb"[\s,]+")
_MIN_TOKENS = 3   # 숫자가 이보다 적으면 우연히 맞은 것일 가능성이 커서 auto 에서 시도하지 않는다


def _tokens(data: bytes) -> list[bytes]:
    return [t for t in _SEP.split(data.strip()) if t]


def _numbers(data: bytes, digits: bytes, base: int, what: str) -> list[int]:
    out = []
    for token in _tokens(data):
        if not token or any(ch not in digits for ch in token):
            raise TransformError(f"{what} 이 아닌 값이 있습니다: {token[:20]!r}")
        out.append(int(token, base))
    return out


def _to_bytes(numbers: list[int], what: str) -> bytes:
    """0~255 는 바이트 하나로, 그보다 크면 유니코드 코드포인트로 보고 UTF-8 로 적는다."""
    out = bytearray()
    for n in numbers:
        if n <= 0xFF:
            out.append(n)
        elif n <= 0x10FFFF:
            out += chr(n).encode("utf-8", "surrogatepass")
        else:
            raise TransformError(f"{what} 값이 너무 큽니다: {n}")
    return bytes(out)


@register
class Binary(Transform):
    name = "binary"
    aliases = ("bin",)
    description = "2진수 (예: 01100110 01101100, 공백은 있어도 없어도 됨)"

    def decode(self, data, key=None):
        bits = b"".join(data.split())
        if any(ch not in b"01" for ch in bits):
            raise TransformError("2진수는 0 과 1 로만 이뤄져야 합니다")
        if len(bits) % 8:
            raise TransformError(f"비트 수가 8의 배수가 아닙니다 ({len(bits)}비트)")
        return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))

    def encode(self, data, key=None):
        return " ".join(f"{b:08b}" for b in data).encode("ascii")

    def looks_like(self, data):
        if not _BINARY_RE.match(data):
            return False
        bits = b"".join(data.split())
        return len(bits) >= 16 and len(bits) % 8 == 0


@register
class Decimal(Transform):
    name = "decimal"
    aliases = ("dec", "ascii")
    description = "10진 코드 (예: 102 108 97 103, 쉼표 구분도 가능)"

    def decode(self, data, key=None):
        return _to_bytes(_numbers(data, b"0123456789", 10, "10진수"), "10진 코드")

    def encode(self, data, key=None):
        return " ".join(str(b) for b in data).encode("ascii")

    def looks_like(self, data):
        tokens = _tokens(data)
        return (len(tokens) >= _MIN_TOKENS
                and all(t.isdigit() and len(t) <= 3 and int(t) <= 255 for t in tokens))


@register
class Octal(Transform):
    name = "octal"
    aliases = ("oct",)
    description = "8진 코드 (예: 146 154 141 147)"

    def decode(self, data, key=None):
        return _to_bytes(_numbers(data, b"01234567", 8, "8진수"), "8진 코드")

    def encode(self, data, key=None):
        return " ".join(f"{b:o}" for b in data).encode("ascii")

    def looks_like(self, data):
        tokens = _tokens(data)
        return (len(tokens) >= _MIN_TOKENS
                and all(len(t) <= 3 and all(ch in b"01234567" for ch in t) and int(t, 8) <= 255 for t in tokens))


@register
class A1Z26(Transform):
    name = "a1z26"
    description = "A1Z26 (1=a ... 26=z, 예: 6 12 1 7). 대소문자·기호는 복원되지 않음"
    lossy = True

    def decode(self, data, key=None):
        out = bytearray()
        for token in re.split(rb"[\s,\-]+", data.strip()):
            if not token:
                continue
            if not token.isdigit() or not 1 <= int(token) <= 26:
                raise TransformError(f"A1Z26 은 1~26 숫자만 씁니다: {token[:20]!r}")
            out.append(0x60 + int(token))
        return bytes(out)

    def encode(self, data, key=None):
        letters = [b for b in data.lower() if 0x61 <= b <= 0x7A]
        return " ".join(str(b - 0x60) for b in letters).encode("ascii")

    def looks_like(self, data):
        tokens = [t for t in re.split(rb"[\s,\-]+", data.strip()) if t]
        return len(tokens) >= _MIN_TOKENS and all(t.isdigit() and 1 <= int(t) <= 26 for t in tokens)
