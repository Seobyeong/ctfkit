from ctfkit.analysis import chi_squared, letter_counts, looks_encoded
from ctfkit.registry import Transform, TransformError, register


def shift_letters(data: bytes, shift: int) -> bytes:
    """알파벳만 shift 칸 밀고 나머지 바이트는 그대로 둔다."""
    out = bytearray()
    for b in data:
        if 0x41 <= b <= 0x5A:
            out.append((b - 0x41 + shift) % 26 + 0x41)
        elif 0x61 <= b <= 0x7A:
            out.append((b - 0x61 + shift) % 26 + 0x61)
        else:
            out.append(b)
    return bytes(out)


def _parse_shift(key):
    try:
        return int(key) % 26
    except (TypeError, ValueError):
        raise TransformError(f"시저 키는 정수(이동 칸 수)여야 합니다: {key}") from None


@register
class Caesar(Transform):
    name = "caesar"
    description = "시저 암호 (키: 이동 칸 수, 예: 3)"
    needs_key = True
    example_key = "3"

    def decode(self, data, key=None):
        return shift_letters(data, -_parse_shift(key))

    def encode(self, data, key=None):
        return shift_letters(data, _parse_shift(key))

    def looks_like(self, data):
        return sum(letter_counts(data)) > 0 and not looks_encoded(data)

    def guess_keys(self, data, limit=3):
        if sum(letter_counts(data)) == 0:
            return []
        # 26가지를 모두 풀어 보고, 영어 빈도에 가장 가까운 순서로 정렬 (빈도 분석)
        shifts = sorted(range(26), key=lambda k: chi_squared(shift_letters(data, -k)))
        return [str(k) for k in shifts[:limit]]
