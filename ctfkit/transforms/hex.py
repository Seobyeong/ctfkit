import re

from ctfkit.registry import Transform, TransformError, register

_HEX_RE = re.compile(rb"^(0x)?[0-9a-fA-F\s]+$")


@register
class Hex(Transform):
    name = "hex"
    aliases = ("base16",)
    description = "16진수 (예: 666c6167, 0x666c6167, 66 6c 61 67)"

    def decode(self, data, key=None):
        data = data.strip()
        if data[:2].lower() == b"0x":
            data = data[2:]
        try:
            # bytes.fromhex 는 str 만 받고, 바이트 사이의 공백은 알아서 무시한다
            return bytes.fromhex(data.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as e:
            raise TransformError(f"hex 디코딩 실패: {e}") from e

    def encode(self, data, key=None):
        return data.hex().encode("ascii")

    def looks_like(self, data):
        return bool(_HEX_RE.match(data.strip()))
