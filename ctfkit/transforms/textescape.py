"""글자를 코드로 적는 이스케이프 표기: HTML 엔티티, \\uXXXX·\\xNN, quoted-printable.

웹 문제의 소스나 응답에 자주 나온다. 세 변환 모두 "표기된 부분만 바꾸고 나머지 글자는 그대로 둔다".
"""

import html.entities
import re

from ctfkit.registry import Transform, register

_ENTITY_RE = re.compile(rb"&#[xX]([0-9a-fA-F]{1,6});?|&#([0-9]{1,7});?|&([A-Za-z][A-Za-z0-9]{1,30});")
_ESCAPE_RE = re.compile(rb"\\U([0-9a-fA-F]{8})|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")
_QP_RE = re.compile(rb"=([0-9A-Fa-f]{2})|=\r?\n")


def _codepoint(cp: int) -> bytes | None:
    """0~255 는 바이트 하나로, 그보다 크면 UTF-8 로. 유니코드 범위를 벗어나면 None."""
    if cp <= 0xFF:
        return bytes([cp])
    if cp <= 0x10FFFF:
        return chr(cp).encode("utf-8", "surrogatepass")
    return None


@register
class HtmlEntity(Transform):
    name = "html"
    aliases = ("entity",)
    description = "HTML 엔티티 (예: &#102;&#x6c;&lt;)"

    def decode(self, data, key=None):
        def replace(match):
            hex_code, dec_code, name = match.groups()
            if name is not None:
                cp = html.entities.name2codepoint.get(name.decode("ascii"))
                return match.group(0) if cp is None else _codepoint(cp)
            out = _codepoint(int(hex_code, 16) if hex_code is not None else int(dec_code))
            return match.group(0) if out is None else out

        return _ENTITY_RE.sub(replace, data)

    def encode(self, data, key=None):
        return "".join(f"&#{b};" for b in data).encode("ascii")

    def looks_like(self, data):
        return any(m.group(0) != self.decode(m.group(0)) for m in _ENTITY_RE.finditer(data[:4096]))


@register
class Escape(Transform):
    name = "escape"
    aliases = ("unicode",)
    description = "문자열 이스케이프 (예: \\u0066\\x6c)"

    def decode(self, data, key=None):
        def replace(match):
            code = next(g for g in match.groups() if g is not None)
            out = _codepoint(int(code, 16))
            return match.group(0) if out is None else out

        return _ESCAPE_RE.sub(replace, data)

    def encode(self, data, key=None):
        return "".join(f"\\x{b:02x}" for b in data).encode("ascii")

    def looks_like(self, data):
        return bool(_ESCAPE_RE.search(data))


@register
class QuotedPrintable(Transform):
    name = "qp"
    aliases = ("quoted-printable",)
    description = "quoted-printable (예: =66=6C=61=67, 이메일 본문 인코딩)"

    def decode(self, data, key=None):
        # "=XX" 는 바이트 하나, 줄 끝의 "=" 는 줄 이어 쓰기 표시라 지운다
        return _QP_RE.sub(lambda m: bytes([int(m.group(1), 16)]) if m.group(1) else b"", data)

    def encode(self, data, key=None):
        return "".join(f"={b:02X}" for b in data).encode("ascii")

    def looks_like(self, data):
        # "=" 하나는 base64 패딩이나 수식에도 나온다. 두 번 이상 이어질 때만 시도한다
        return bool(re.search(rb"(=[0-9A-Fa-f]{2}){2}", data))
