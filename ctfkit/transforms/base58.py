"""Base58 (비트코인 알파벳). 표준 라이브러리만 사용."""

import re

from ctfkit.registry import Transform, TransformError, register

# 비트코인/IPFS 에서 쓰는 알파벳: 0 O I l 처럼 헷갈리는 글자를 뺀 58글자
_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(_ALPHABET)}
_BASE58_RE = re.compile(b"^[" + re.escape(_ALPHABET) + b"]+$")


@register
class Base58(Transform):
    name = "base58"
    aliases = ("b58",)
    description = "Base58 (Bitcoin 알파벳)"

    def decode(self, data, key=None):
        s = data.strip()
        if not s:
            return b""
        num = 0
        for ch in s:
            if ch not in _INDEX:
                raise TransformError(f"base58 알파벳이 아닌 글자: {bytes([ch])!r}")
            num = num * 58 + _INDEX[ch]
        body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
        # 맨 앞의 '1' 들은 각각 0x00 바이트 하나를 뜻한다
        pad = len(s) - len(s.lstrip(b"1"))
        return b"\x00" * pad + body

    def encode(self, data, key=None):
        num = int.from_bytes(data, "big")
        out = bytearray()
        while num > 0:
            num, rem = divmod(num, 58)
            out.append(_ALPHABET[rem])
        out.reverse()
        pad = len(data) - len(data.lstrip(b"\x00"))
        return bytes([_ALPHABET[0]]) * pad + bytes(out)

    def looks_like(self, data):
        s = data.strip()
        return bool(s) and bool(_BASE58_RE.match(s))
