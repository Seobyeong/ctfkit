import base64
import binascii
import re

from ctfkit.registry import Transform, TransformError, register

_BASE32_RE = re.compile(rb"^[A-Z2-7]+=*$", re.IGNORECASE)


@register
class Base32(Transform):
    name = "base32"
    aliases = ("b32",)
    description = "Base32 (RFC 4648)"

    def decode(self, data, key=None):
        data = data.strip()
        # base64 와 마찬가지로 빠진 '=' 패딩을 채운다 (base32 는 8글자 단위)
        data += b"=" * (-len(data) % 8)
        try:
            return base64.b32decode(data, casefold=True)
        except binascii.Error as e:
            raise TransformError(f"base32 디코딩 실패: {e}") from e

    def encode(self, data, key=None):
        return base64.b32encode(data)

    def looks_like(self, data):
        return bool(_BASE32_RE.match(data.strip()))
