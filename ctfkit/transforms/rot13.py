import string

from ctfkit.registry import Transform, register

# 알파벳만 13칸 밀고 나머지 바이트는 그대로 두는 변환표
_TABLE = bytes.maketrans(
    (string.ascii_lowercase + string.ascii_uppercase).encode(),
    (string.ascii_lowercase[13:] + string.ascii_lowercase[:13]
     + string.ascii_uppercase[13:] + string.ascii_uppercase[:13]).encode(),
)


@register
class Rot13(Transform):
    name = "rot13"
    description = "ROT13 (알파벳을 13칸 회전, 인코딩과 디코딩이 같음)"

    def decode(self, data, key=None):
        return data.translate(_TABLE)

    def encode(self, data, key=None):
        return data.translate(_TABLE)

    def looks_like(self, data):
        return any(chr(b).isalpha() for b in data if b < 128)
