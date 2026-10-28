"""auto 엔진의 점수 함수."""

import re

from ctfkit.analysis import text_score
from ctfkit.flags import find_flag


def score(data: bytes, pattern: re.Pattern) -> float:
    """후보의 점수 (0~1). 플래그가 있으면 1, 아니면 텍스트다운 정도."""
    if find_flag(data, pattern):
        return 1.0
    return text_score(data)
