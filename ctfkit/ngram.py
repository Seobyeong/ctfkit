"""영어 글자 n-gram(바이그램) 점수.

글자 '빈도'만 보는 카이제곱은 글자 구성만 맞으면 높은 점수를 주므로,
비즈네르처럼 각 글자를 서로 다른 칸으로 민 경우 틀린 키도 영어처럼 보일 수 있다.
바이그램(연속한 두 글자) 로그확률을 쓰면 "th, he, in" 같은 실제 영어 연쇄를
얼마나 따르는지를 평가하므로, 키가 조금만 틀려도 점수가 뚜렷이 떨어진다.

모델은 저장소에 포함한 영어 코퍼스(``data/english.txt``)에서 한 번 계산해 캐싱한다.
"""

import math
from functools import lru_cache
from importlib import resources

# add-k 스무딩 상수: 코퍼스에 없는 바이그램도 0 이 아닌 작은 확률을 갖게 한다.
_SMOOTHING = 0.1


def _letters(data: bytes) -> bytes:
    """대문자 알파벳(A~Z)만 남긴다. 그 외 바이트는 버린다."""
    return bytes(b for b in data.upper() if 0x41 <= b <= 0x5A)


@lru_cache(maxsize=1)
def _bigram_logprob() -> list[float]:
    """26×26 바이그램 로그확률 표를 코퍼스에서 만들어 캐싱한다.

    인덱스 ``a*26 + b`` 가 글자 a 다음에 b 가 올 로그확률 log P(b|a).
    """
    corpus = resources.files("ctfkit.data").joinpath("english.txt").read_bytes()
    letters = _letters(corpus)

    counts = [_SMOOTHING] * (26 * 26)
    for a, b in zip(letters, letters[1:]):
        counts[(a - 0x41) * 26 + (b - 0x41)] += 1.0

    logprob = [0.0] * (26 * 26)
    for a in range(26):
        row = counts[a * 26:(a + 1) * 26]
        total = sum(row)
        base = a * 26
        for b in range(26):
            logprob[base + b] = math.log(row[b] / total)
    return logprob


def bigram_score(data: bytes) -> float:
    """바이그램 평균 로그확률 (클수록 영어다움). 글자가 2개 미만이면 -inf."""
    letters = _letters(data)
    if len(letters) < 2:
        return float("-inf")
    table = _bigram_logprob()
    total = 0.0
    for a, b in zip(letters, letters[1:]):
        total += table[(a - 0x41) * 26 + (b - 0x41)]
    return total / (len(letters) - 1)
