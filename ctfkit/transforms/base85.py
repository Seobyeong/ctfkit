"""Base85 두 변종: base85(RFC1924/Git, Python b85)와 ascii85(Adobe, Python a85).

표준 라이브러리(base64)만 사용. CTF 마다 쓰는 변종이 달라 둘 다 제공한다.
"""

import base64
import binascii

from ctfkit.analysis import looks_encoded, printable_ratio
from ctfkit.registry import Transform, TransformError, register

MIN_AUTO_LENGTH = 10


def _decodes_to_text(transform, data: bytes) -> bool:
    """auto 가 이 변환을 시도할 만한가.

    base85 는 알파벳이 85자나 돼서 웬만한 글자열이 오류 없이 디코드된다. 아무 데나 시도하면 쓰레기 후보가
    탐색을 채운다. 그래서 "디코드 결과가 전부 출력 가능한 글자" 일 때만 시도한다. 무작위 글자열이 우연히
    이 조건을 통과할 확률은 5글자 묶음 하나당 2% 안팎이라, 10글자만 넘어도 거의 걸러진다.
    base64 나 hex 로 읽히는 덩어리는 그쪽 변환이 맡는다.
    """
    s = data.strip()
    if len(s) < MIN_AUTO_LENGTH or looks_encoded(s) or any(b <= 0x20 or b >= 0x7F for b in s):
        return False
    try:
        out = transform.decode(s)
    except TransformError:
        return False
    return len(out) >= 4 and printable_ratio(out) == 1.0


@register
class Base85(Transform):
    name = "base85"
    aliases = ("b85",)
    description = "Base85 (RFC1924/Git 알파벳, Python b85)"

    def decode(self, data, key=None):
        try:
            return base64.b85decode(data.strip())
        except (ValueError, binascii.Error) as e:
            raise TransformError(f"base85 디코딩 실패: {e}") from e

    def encode(self, data, key=None):
        return base64.b85encode(data)

    def looks_like(self, data):
        return _decodes_to_text(self, data)


@register
class Ascii85(Transform):
    name = "ascii85"
    aliases = ("a85",)
    description = "ASCII85 (Adobe, <~ ~> 감싸기 지원)"

    def decode(self, data, key=None):
        s = data.strip()
        # Adobe 변종은 <~ ... ~> 로 감싸기도 한다
        adobe = s.startswith(b"<~")
        try:
            return base64.a85decode(s, adobe=adobe)
        except (ValueError, binascii.Error) as e:
            raise TransformError(f"ascii85 디코딩 실패: {e}") from e

    def encode(self, data, key=None):
        return base64.a85encode(data)

    def looks_like(self, data):
        return _decodes_to_text(self, data)
