from ctfkit.analysis import (
    ENGLISH_IC,
    chi_squared,
    index_of_coincidence,
    letter_counts,
    letter_ratio,
    looks_encoded,
)
from ctfkit.ngram import bigram_score
from ctfkit.registry import Transform, TransformError, register
from ctfkit.transforms.caesar import shift_letters

MIN_LETTERS = 20      # 이보다 짧으면 통계가 의미 없어서 키 추정을 하지 않는다
MAX_KEY_LENGTH = 16
# 최고 IC 의 이 비율 이상이면 키 길이 후보로 본다.
# 고정 기준(예: 0.055)은 암호문이 짧을 때 진짜 길이의 IC 가 살짝 못 미쳐 놓치는 일이 있다.
IC_RELATIVE_THRESHOLD = 0.9
# 언덕 오르기 점수 계산에 쓰는 최대 글자 수. 키가 반복되므로 앞부분만 봐도
# 전체 패턴을 대표한다. 긴 입력에서 매 시도마다 전체를 점수화하는 비용을 막는다.
HILL_SAMPLE = 1500
# auto 가 쓰는 빠른 추정에서 보는 최대 글자 수. 키 길이 16 까지 열마다 수십 글자면 빈도 분석에 충분하다.
GUESS_SAMPLE = 800
# 빠른 추정에서 키를 한 번 다듬을 때 보는 글자 수와 반복 횟수. 열별 빈도 분석은 첫 글자 하나쯤 틀리기 쉬운데,
# 짧은 표본으로 한 바퀴만 돌아도 대부분 바로잡힌다 (전체를 여러 바퀴 도는 것은 crack_keys 의 몫).
QUICK_SAMPLE = 300
QUICK_PASSES = 1


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


def _decrypt_letters(letters: bytes, shifts: list[int]) -> bytes:
    """대문자 글자열을 키(shifts)로 복호화한다 (점수 계산 전용)."""
    n = len(shifts)
    return bytes((letters[i] - 0x41 - shifts[i % n]) % 26 + 0x41 for i in range(len(letters)))


def _hill_climb(sample: bytes, shifts: list[int], max_passes: int | None = None) -> list[int]:
    """시드 키에서 출발해, 각 위치의 이동량을 바꿔 보며 바이그램 점수가
    오르는 쪽으로 키를 다듬는다 (언덕 오르기). 더 오르지 않으면 멈춘다.

    열별 카이제곱은 열마다 글자가 적은 짧은 암호문에서 흔들리지만,
    언덕 오르기는 전체 복호문의 글자 연쇄 점수를 쓰므로 그 약점을 보완한다.
    """
    shifts = list(shifts)
    best = bigram_score(_decrypt_letters(sample, shifts))
    improved = True
    passes = 0
    while improved and (max_passes is None or passes < max_passes):
        improved = False
        passes += 1
        for i in range(len(shifts)):
            current = shifts[i]
            best_shift = current
            for s in range(26):
                if s == current:
                    continue
                shifts[i] = s
                score = bigram_score(_decrypt_letters(sample, shifts))
                if score > best:
                    best, best_shift, improved = score, s, True
            shifts[i] = best_shift
    return shifts


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
    text_cipher = True
    aliases = ("vig",)
    description = "비즈네르 암호 (키: 알파벳, 예: KEY)"
    needs_key = True
    example_key = "KEY"

    def decode(self, data, key=None):
        return _apply(data, _parse_key(key), -1)

    def encode(self, data, key=None):
        return _apply(data, _parse_key(key), 1)

    def looks_like(self, data):
        return (sum(letter_counts(data)) >= MIN_LETTERS and letter_ratio(data) >= 0.5
                and not looks_encoded(data))

    def guess_keys(self, data, limit=3):
        """빠른 키 추정 (auto 탐색이 노드마다 부른다): 열별 빈도 분석 + 짧은 표본으로 한 바퀴 다듬기.

        언덕 오르기는 26 × 키 길이 × 반복 횟수만큼 복호문 전체를 다시 점수화해서 무겁다.
        auto 가 긴 입력의 모든 후보에 그것을 돌리면 문제 하나에 수십 초가 걸린다. 철저한 추정은 crack_keys 가 한다.
        """
        letters = _only_letters(data)[:GUESS_SAMPLE]
        if len(letters) < MIN_LETTERS:
            return []
        quick = letters[:QUICK_SAMPLE]
        keys = []
        for length in _key_lengths(letters, limit):
            shifts = _hill_climb(quick, self._seed(letters, length), max_passes=QUICK_PASSES)
            key = _minimal_period("".join(chr(ord("A") + s) for s in shifts))
            if key not in keys:
                keys.append(key)
        keys.sort(key=lambda k: bigram_score(_decrypt_letters(quick, _parse_key(k))), reverse=True)
        return keys[:limit]

    @staticmethod
    def _seed(letters: bytes, length: int) -> list[int]:
        """각 열을 시저 암호로 보고 빈도 분석으로 이동 칸 수를 구한다."""
        return [min(range(26), key=lambda k: chi_squared(shift_letters(letters[i::length], -k)))
                for i in range(length)]

    def crack_keys(self, data, limit=3):
        """철저한 키 추정 (crack 명령 전용): 빈도 분석으로 잡은 시드를 언덕 오르기로 다듬는다."""
        letters = _only_letters(data)
        if len(letters) < MIN_LETTERS:
            return []

        sample = letters[:HILL_SAMPLE]
        keys = []
        for length in _key_lengths(letters, limit):
            seed = self._seed(letters, length)
            # 시드에서 언덕 오르기로 키를 다듬는다 (짧은 암호문 보완)
            refined = _hill_climb(sample, seed)
            for shifts in (refined, seed):
                key = _minimal_period("".join(chr(ord("A") + s) for s in shifts))
                if key not in keys:
                    keys.append(key)

        # 복호문의 바이그램 점수로 정렬한다. 글자 빈도(카이제곱)와 달리 글자 연쇄를 보므로
        # 틀린 긴 키가 과적합으로 앞서는 일이 줄어, 짧고 올바른 키가 위로 온다.
        keys.sort(key=lambda k: bigram_score(_apply(data, _parse_key(k), -1)), reverse=True)
        return keys[:limit]
