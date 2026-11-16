# 파일 이름 뒤의 _ 는 표준 라이브러리 base64 와 이름이 겹치지 않게 하기 위함
import base64
import binascii
import re

from ctfkit.registry import Transform, TransformError, register

# URL-safe 변종(RFC 4648 5절)은 + / 대신 - _ 를 쓴다. JWT 가 이 방식이라 CTF 에 자주 나온다
_BASE64_RE = re.compile(rb"^[A-Za-z0-9+/_-]+={0,2}$")
_URLSAFE = bytes.maketrans(b"-_", b"+/")


@register
class Base64(Transform):
    name = "base64"
    aliases = ("b64",)
    description = "Base64 (RFC 4648, URL-safe 알파벳도 받음)"

    def decode(self, data, key=None):
        data = data.strip().translate(_URLSAFE)
        # CTF 문제에서는 끝의 '=' 패딩이 빠진 경우가 많아서 채워준다
        data += b"=" * (-len(data) % 4)
        try:
            # validate=True: base64 문자가 아닌 것이 섞여 있으면 무시하지 않고 오류
            return base64.b64decode(data, validate=True)
        except binascii.Error as e:
            raise TransformError(f"base64 디코딩 실패: {e}") from e

    def encode(self, data, key=None):
        return base64.b64encode(data)

    def looks_like(self, data):
        return bool(_BASE64_RE.match(data.strip()))
