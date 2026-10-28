import re
from urllib.parse import quote_from_bytes, unquote_to_bytes

from ctfkit.registry import Transform, register

_PERCENT_RE = re.compile(rb"%[0-9a-fA-F]{2}")


@register
class Url(Transform):
    name = "url"
    aliases = ("percent",)
    description = "URL 퍼센트 인코딩 (예: flag%7Bhi%7D)"

    def decode(self, data, key=None):
        # 폼 데이터에서는 공백이 '+' 로 인코딩되므로 먼저 되돌린다
        return unquote_to_bytes(data.replace(b"+", b" "))

    def encode(self, data, key=None):
        # safe="" : '/' 까지 포함해 영숫자와 -._~ 를 제외한 모든 문자를 인코딩
        return quote_from_bytes(data, safe="").encode("ascii")

    def looks_like(self, data):
        return bool(_PERCENT_RE.search(data))
