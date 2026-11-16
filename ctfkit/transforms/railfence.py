"""레일 펜스 암호: 글자를 지그재그로 여러 줄(레일)에 적은 뒤 줄 단위로 이어 붙인 전치 암호.

글자 자체는 바뀌지 않고 순서만 섞인다. 그래서 빈도 분석으로는 풀 수 없고, 레일 수를 하나씩 넣어 보며
플래그 모양이 나오는지를 본다.
"""

from ctfkit.analysis import looks_encoded, printable_ratio
from ctfkit.flags import compile_flag_pattern, flag_prefixes
from ctfkit.registry import Transform, TransformError, register

MAX_RAILS = 10


def _parse_rails(key) -> int:
    try:
        rails = int(key)
    except (TypeError, ValueError):
        raise TransformError(f"레일 펜스 키는 레일 수(2 이상의 정수)여야 합니다: {key}") from None
    if rails < 2:
        raise TransformError(f"레일 수는 2 이상이어야 합니다: {rails}")
    return rails


def _pattern(length: int, rails: int) -> list[int]:
    """글자 위치마다 몇 번째 레일에 놓이는지 (0, 1, 2, 1, 0, 1, ...)."""
    out, rail, step = [], 0, 1
    for _ in range(length):
        out.append(rail)
        if rails > 1:
            if rail == 0:
                step = 1
            elif rail == rails - 1:
                step = -1
            rail += step
    return out


@register
class RailFence(Transform):
    name = "railfence"
    text_cipher = True
    aliases = ("rail",)
    description = "레일 펜스 암호 (키: 레일 수, 예: 3)"
    needs_key = True
    example_key = "3"

    def encode(self, data, key=None):
        rails = _parse_rails(key)
        pattern = _pattern(len(data), rails)
        return bytes(data[i] for rail in range(rails) for i in range(len(data)) if pattern[i] == rail)

    def decode(self, data, key=None):
        rails = _parse_rails(key)
        pattern = _pattern(len(data), rails)
        # 암호문은 "레일 0 의 글자들, 레일 1 의 글자들, ..." 순서다. 각 글자의 원래 위치를 구해 되돌린다
        order = [i for rail in range(rails) for i in range(len(data)) if pattern[i] == rail]
        out = bytearray(len(data))
        for position, original in enumerate(order):
            out[original] = data[position]
        return bytes(out)

    def looks_like(self, data):
        # 전치 암호라 플래그의 괄호가 그대로 남아 있다. 괄호가 없으면 맞는지 확인할 방법이 없어 시도하지 않는다
        s = data.strip()
        return (len(s) >= 6 and b"{" in s and b"}" in s
                and printable_ratio(s) == 1.0 and not looks_encoded(s))

    def guess_keys(self, data, limit=3):
        s = data.strip()
        if not self.looks_like(s):
            return []
        pattern = compile_flag_pattern()
        prefixes = tuple((p + "{").encode() for p in flag_prefixes())

        def rank(rails: int) -> tuple:
            plain = self.decode(s, str(rails))
            # 플래그 형식에 맞음 > 알려진 접두사로 시작 > "{ 가 앞, } 가 맨 끝" 순으로 그럴듯하다
            return (
                not pattern.search(plain),
                not plain.startswith(prefixes),
                not (plain.endswith(b"}") and plain.index(b"{") < plain.index(b"}")),
                rails,
            )

        candidates = range(2, min(MAX_RAILS, len(s) - 1) + 1)
        return [str(r) for r in sorted(candidates, key=rank)[:limit]]
