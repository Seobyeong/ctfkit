import re

from ctfkit.registry import Transform, TransformError, register

_HEX_RE = re.compile(rb"^(0[xX])?[0-9a-fA-F\s]+$")
# 바이트마다 0x 를 붙이고 공백·쉼표로 구분한 목록 (C 배열을 그대로 붙여 넣은 꼴)
_HEX_LIST_RE = re.compile(rb"^\s*0[xX][0-9a-fA-F]{1,2}(\s*[,\s]\s*0[xX][0-9a-fA-F]{1,2})+\s*,?\s*$")


@register
class Hex(Transform):
    name = "hex"
    aliases = ("base16",)
    description = "16진수 (예: 666c6167, 0x666c6167, 66 6c 61 67, 0x66 0x6c)"

    def decode(self, data, key=None):
        data = data.strip()
        if _HEX_LIST_RE.match(data):
            tokens = re.findall(rb"0[xX]([0-9a-fA-F]{1,2})", data)
            return bytes(int(t, 16) for t in tokens)
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
        return bool(_HEX_RE.match(data.strip()) or _HEX_LIST_RE.match(data))
