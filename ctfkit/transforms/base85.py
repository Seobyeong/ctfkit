"""Base85 두 변종: base85(RFC1924/Git, Python b85)와 ascii85(Adobe, Python a85).

표준 라이브러리(base64)만 사용. CTF 마다 쓰는 변종이 달라 둘 다 제공한다.
"""

import base64
import binascii

from ctfkit.registry import Transform, TransformError, register


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
        # b85/a85 는 거의 모든 바이트열이 '그럴듯하게' 디코드돼 auto 를 오염시키므로
        # 자동 탐색에선 제외하고 codec 으로 명시해 쓰게 한다
        return False


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
        return False  # base85 과 같은 이유로 auto 에서 제외
