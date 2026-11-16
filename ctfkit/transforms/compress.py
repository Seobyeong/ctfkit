"""압축 풀기: gzip, zlib. base64 나 hex 를 풀었더니 압축된 바이트가 나오는 문제에 쓴다.

풀린 크기에 상한을 둔다. 몇 KB 가 몇 GB 로 풀리도록 만든 입력(압축 폭탄)으로 메모리를 다 쓰지 않게 한다.
"""

import gzip
import zlib

from ctfkit.registry import Transform, TransformError, register

MAX_OUTPUT = 16 * 1024 * 1024


def _inflate(data: bytes, wbits: int, what: str) -> bytes:
    try:
        engine = zlib.decompressobj(wbits)
        out = engine.decompress(data, MAX_OUTPUT)
        if engine.unconsumed_tail:
            raise TransformError(f"{what}: 풀린 크기가 {MAX_OUTPUT // (1024 * 1024)}MB 를 넘어 중단했습니다")
        return out
    except zlib.error as e:
        raise TransformError(f"{what} 압축 풀기 실패: {e}") from e


@register
class Gzip(Transform):
    name = "gzip"
    aliases = ("gunzip",)
    description = "gzip 압축 풀기 (인코딩은 압축)"

    def decode(self, data, key=None):
        return _inflate(data, 16 + zlib.MAX_WBITS, "gzip")

    def encode(self, data, key=None):
        return gzip.compress(data, mtime=0)   # mtime=0: 같은 입력이면 항상 같은 결과

    def looks_like(self, data):
        return data[:3] == b"\x1f\x8b\x08"


@register
class Zlib(Transform):
    name = "zlib"
    aliases = ("deflate",)
    description = "zlib 압축 풀기 (인코딩은 압축)"

    def decode(self, data, key=None):
        return _inflate(data, zlib.MAX_WBITS, "zlib")

    def encode(self, data, key=None):
        return zlib.compress(data)

    def looks_like(self, data):
        # zlib 머리 2바이트: 첫 바이트의 아래 4비트가 8(deflate), 두 바이트를 16비트로 읽으면 31의 배수
        return len(data) >= 6 and data[0] & 0x0F == 8 and data[0] >> 4 <= 7 and (data[0] << 8 | data[1]) % 31 == 0
