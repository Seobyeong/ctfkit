from itertools import cycle

from ctfkit.registry import Transform, TransformError, register


def parse_key(key: str | None) -> bytes:
    """키 문자열을 bytes 로 바꾼다. '0x' 로 시작하면 16진수, 아니면 문자열 그대로."""
    if not key:
        raise TransformError("XOR 키가 비어 있습니다")
    if key[:2].lower() == "0x":
        try:
            return bytes.fromhex(key[2:])
        except ValueError as e:
            raise TransformError(f"잘못된 16진수 키: {key} ({e})") from e
    return key.encode("utf-8")


@register
class Xor(Transform):
    name = "xor"
    description = "반복 키 XOR (키: 0x20, 0x4142 처럼 16진수 또는 일반 문자열)"
    needs_key = True
    example_key = "0x20"

    def decode(self, data, key=None):
        key_bytes = parse_key(key)
        # 키가 데이터보다 짧으면 반복해서 사용한다
        return bytes(b ^ k for b, k in zip(data, cycle(key_bytes)))

    def encode(self, data, key=None):
        # XOR 은 같은 키로 한 번 더 하면 원래대로 돌아온다
        return self.decode(data, key)
