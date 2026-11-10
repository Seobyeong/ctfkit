"""v0.16 crack 심화 테스트: 영어 바이그램 점수 + 비즈네르 언덕 오르기."""

from ctfkit import registry
from ctfkit.ngram import bigram_score

# 약 75글자 — 기존 열별 카이제곱만으로는 키가 흔들리기 시작하는 길이대.
SHORT = (
    b"the measure of intelligence is the ability to change "
    b"and to adapt to new situations quickly"
)


def _enc(data, key):
    return registry.get("vigenere").encode(data, key)


# --- 바이그램 점수 ---

def test_bigram_english_beats_scramble():
    english = b"the quick brown fox jumps over the lazy dog every morning"
    scramble = b"xqzjkwvbgpmfdhtlrcsnyaoeiu" * 3
    assert bigram_score(english) > bigram_score(scramble)


def test_bigram_too_few_letters():
    assert bigram_score(b"a") == float("-inf")
    assert bigram_score(b"1234") == float("-inf")


def test_bigram_is_mean_logprob_negative():
    # 로그확률 평균이므로 항상 음수이고 유한해야 한다
    s = bigram_score(b"the flag is hidden somewhere")
    assert s < 0 and s != float("-inf")


# --- 짧은 비즈네르 복구 (언덕 오르기 효과) ---

def test_vigenere_short_recovers_key():
    v = registry.get("vigenere")
    for key in ("SECRET", "KEY", "LEMONADE"):
        ct = _enc(SHORT, key)
        assert v.guess_keys(ct, limit=5)[0] == key


def test_vigenere_short_decrypts_back():
    v = registry.get("vigenere")
    ct = _enc(SHORT, "SECRET")
    best = v.guess_keys(ct, limit=5)[0]
    assert v.decode(ct, best) == SHORT


def test_vigenere_long_still_works():
    # 긴 입력에서도 기존처럼 1순위로 복구되어야 한다 (회귀 방지)
    long_pt = SHORT * 4
    v = registry.get("vigenere")
    ct = _enc(long_pt, "CRYPTO")
    assert v.guess_keys(ct, limit=5)[0] == "CRYPTO"
