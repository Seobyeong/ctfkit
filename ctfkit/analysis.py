"""암호 분석에 쓰는 통계 함수 모음 (출력 가능 비율, 영어 빈도, 카이제곱, 일치 지수)."""

import re

# 영어 알파벳 a~z 의 출현 빈도 (합계 약 1)
ENGLISH_FREQ = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
]

# 영어 문장의 일치 지수(IC). 무작위 알파벳은 1/26 ≈ 0.038
ENGLISH_IC = 0.066

_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

# 영어 문장·플래그에 흔히 나오는 알파벳 외 문자 (숫자, 공백, 자주 쓰는 문장부호)
_COMMON_TEXT = set(b"0123456789 _{}.,!?'\"-:()\n")

# 공백·문장부호 없이 인코딩 문자만으로 이뤄진 덩어리 (base64, hex, base32 등)
_ENCODED_BLOB_RE = re.compile(rb"^[A-Za-z0-9+/=_-]{8,}$")


def printable_ratio(data: bytes) -> float:
    """출력 가능한 ASCII 문자의 비율 (0~1)."""
    if not data:
        return 0.0
    return sum(b in _PRINTABLE for b in data) / len(data)


def letter_counts(data: bytes) -> list[int]:
    """대소문자를 구분하지 않고 a~z 각각의 개수를 센다."""
    counts = [0] * 26
    for b in data:
        if 0x41 <= b <= 0x5A:
            counts[b - 0x41] += 1
        elif 0x61 <= b <= 0x7A:
            counts[b - 0x61] += 1
    return counts


def chi_squared(data: bytes) -> float:
    """영어 빈도와의 카이제곱 거리. 작을수록 영어에 가깝다. 알파벳이 없으면 무한대."""
    counts = letter_counts(data)
    n = sum(counts)
    if n == 0:
        return float("inf")
    return sum((c - n * f) ** 2 / (n * f) for c, f in zip(counts, ENGLISH_FREQ))


def index_of_coincidence(data: bytes) -> float:
    """일치 지수: 임의로 고른 두 글자가 같을 확률. 영어는 약 0.066."""
    counts = letter_counts(data)
    n = sum(counts)
    if n < 2:
        return 0.0
    return sum(c * (c - 1) for c in counts) / (n * (n - 1))


def english_score(data: bytes) -> float:
    """영어 문장에 가까운 정도 (0~1)."""
    counts = letter_counts(data)
    n = sum(counts)
    if n == 0:
        return 0.0
    # 전체 중 텍스트에 흔한 문자의 비율 × 알파벳 빈도가 영어와 비슷한 정도.
    # ~ ^ \ 같은 드문 기호가 많으면 text_ratio 가 낮아진다.
    text_ratio = (n + sum(b in _COMMON_TEXT for b in data)) / len(data)
    fit = 1 / (1 + chi_squared(data) / n)
    return text_ratio * fit


def text_score(data: bytes) -> float:
    """사람이 읽을 수 있는 텍스트일 가능성 (0~1). auto 엔진과 키 추정의 기본 점수."""
    if not data:
        return 0.0
    printable = printable_ratio(data)
    if printable < 0.95:
        # 바이너리에 가까우면 출력 가능 비율만으로 낮게 평가
        return printable * 0.5
    return 0.5 * printable + 0.5 * english_score(data)


def looks_encoded(data: bytes) -> bool:
    """공백 없이 인코딩 문자로만 된 덩어리인가 (예: base64 문자열).

    시저·비즈네르 같은 빈도 분석 기반 변환은 이런 데이터에 적용해도 의미가 없다.
    """
    return bool(_ENCODED_BLOB_RE.match(data.strip()))
