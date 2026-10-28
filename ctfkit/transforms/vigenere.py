from ctfkit.analysis import (
    ENGLISH_IC,
    chi_squared,
    index_of_coincidence,
    letter_counts,
    looks_encoded,
)
from ctfkit.registry import Transform, TransformError, register
from ctfkit.transforms.caesar import shift_letters

MIN_LETTERS = 20      # 이보다 짧으면 통계가 의미 없어서 키 추정을 하지 않는다
MAX_KEY_LENGTH = 16
# 최고 IC 의 이 비율 이상이면 키 길이 후보로 본다.
# 고정 기준(예: 0.055)은 암호문이 짧을 때 진짜 길이의 IC 가 살짝 못 미쳐 놓치는 일이 있다.
IC_RELATIVE_THRESHOLD = 0.9


def _parse_key(key) -> list[int]:
    if not key or not key.isascii() or not key.isalpha():
        raise TransformError(f"비즈네르 키는 알파벳이어야 합니다: {key}")
    return [ord(c) - ord("A") for c in key.upper()]


def _apply(data: bytes, shifts: list[int], sign: int) -> bytes:
    # 알파벳에만 키를 적용하고, 키 위치도 알파벳을 만날 때만 넘어간다 (표준 방식)
    out = bytearray()
    i = 0
    for b in data:
        if 0x41 <= b <= 0x5A:
            out.append((b - 0x41 + sign * shifts[i % len(shifts)]) % 26 + 0x41)
            i += 1
        elif 0x61 <= b <= 0x7A:
            out.append((b - 0x61 + sign * shifts[i % len(shifts)]) % 26 + 0x61)
            i += 1
        else:
            out.append(b)
    return bytes(out)


def _only_letters(data: bytes) -> bytes:
    return bytes(b for b in data.upper() if 0x41 <= b <= 0x5A)


def _minimal_period(key: str) -> str:
    # "KEYKEY" 처럼 반복된 키를 "KEY" 로 줄인다
    for size in range(1, len(key) + 1):
        if len(key) % size == 0 and key[:size] * (len(key) // size) == key:
            return key[:size]
    return key


def _key_lengths(letters: bytes, limit: int) -> list[int]:
    """일치 지수(IC)로 가능성 높은 키 길이를 고른다.

    키 길이 L 로 나눈 각 열은 같은 시저 키로 암호화되었으므로,
    L 이 맞으면 열들의 IC 가 영어 IC 에 가까워진다.
    """
    max_len = min(MAX_KEY_LENGTH, len(letters) // 8)
    scored = []
    for length in range(1, max_len + 1):
        columns = [letters[i::length] for i in range(length)]
        avg_ic = sum(index_of_coincidence(c) for c in columns) / length
        scored.append((length, avg_ic))

    # 진짜 길이의 배수(5 → 10, 15)도 IC 가 높게 나오므로, 기준을 넘는 길이 중 짧은 것부터 고른다
    best_ic = max(ic for _, ic in scored)
    passing = [length for length, ic in scored if ic >= best_ic * IC_RELATIVE_THRESHOLD]
    # 자리가 남으면 영어 IC 에 가까운 순서로 채운다
    rest = sorted((item for item in scored if item[0] not in passing),
                  key=lambda item: abs(item[1] - ENGLISH_IC))
    return (passing + [length for length, _ in rest])[:limit]


@register
class Vigenere(Transform):
    name = "vigenere"
    aliases = ("vig",)
    description = "비즈네르 암호 (키: 알파벳, 예: KEY)"
    needs_key = True
    example_key = "KEY"

    def decode(self, data, key=None):
        return _apply(data, _parse_key(key), -1)

    def encode(self, data, key=None):
        return _apply(data, _parse_key(key), 1)

    def looks_like(self, data):
        return sum(letter_counts(data)) >= MIN_LETTERS and not looks_encoded(data)

    def guess_keys(self, data, limit=3):
        letters = _only_letters(data)
        if len(letters) < MIN_LETTERS:
            return []

        keys = []
        for length in _key_lengths(letters, limit):
            # 각 열을 시저 암호로 보고 빈도 분석으로 이동 칸 수를 구한다
            key = ""
            for i in range(length):
                column = letters[i::length]
                shift = min(range(26), key=lambda k: chi_squared(shift_letters(column, -k)))
                key += chr(ord("A") + shift)
            key = _minimal_period(key)
            if key not in keys:
                keys.append(key)

        # 복호문의 카이제곱으로 다시 정렬하지 않는다: 키가 길수록 열마다 따로 맞춰져서(과적합)
        # 틀린 긴 키가 더 좋아 보이기 때문. 짧은 키 길이 우선 순서를 그대로 쓴다.
        return keys[:limit]
