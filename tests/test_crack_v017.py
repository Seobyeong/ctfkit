"""v0.17 crack 심화 테스트: 반복 키 XOR 의 다중 바이트 키 통계적 추정.

알려진 평문(플래그 접두사) 없이, 해밍 거리로 키 길이를 추정하고 각 자리를
1바이트 XOR 로 풀어 반복 키를 복구하는 경로를 검증한다.
"""

from ctfkit import registry

PARAGRAPH = (
    b"In computer security a vulnerability is a weakness which can be exploited "
    b"by an attacker to perform unauthorized actions within a system before "
    b"vendors release patches. Many researchers publish findings so vendors "
    b"release patches before criminals abuse the flaws in the wild everywhere."
)


def _xor_cmd():
    return registry.get("xor")


def _encrypt(data, key_bytes):
    return _xor_cmd().encode(data, "0x" + key_bytes.hex())


def test_hamming_reference():
    # cryptopals 표준 예제: 두 문자열의 비트 해밍 거리는 37
    from ctfkit.transforms.xor import _hamming
    assert _hamming(b"this is a test", b"wokka wokka!!!") == 37


def test_multibyte_recovers_short_keys():
    # 플래그 접두사 없이도 반복 키를 복구한다 (충분한 길이의 영어 평문)
    x = _xor_cmd()
    for key in (b"KEY", b"SECRET", b"\x13\x37\xca\xfe"):
        ct = _encrypt(PARAGRAPH, key)
        want = "0x" + key.hex()
        assert want in x.crack_keys(ct, limit=3), f"키 {key!r} 복구 실패"


def test_multibyte_top_candidate_is_minimal_period():
    # 같은 평문을 주는 배수 길이(KEYKEY 등)가 아니라 최소 주기 키가 1순위여야 한다
    x = _xor_cmd()
    ct = _encrypt(PARAGRAPH, b"KEY")
    assert x.crack_keys(ct, limit=3)[0] == "0x" + b"KEY".hex()


# 다양한(반복 없는) 영어 — 열마다 서로 다른 글자가 모여 통계가 안정적이다
LONG_TEXT = (
    b"The history of cryptography spans thousands of years, from simple "
    b"substitution ciphers carved on ancient tablets to the complex algorithms "
    b"that protect modern banking and communication. Scholars once hid messages "
    b"by shifting letters, while today machines perform billions of operations "
    b"to keep secrets safe. Every advance in codemaking has been met by an equal "
    b"advance in codebreaking around the world today and tomorrow as well."
)


def test_multibyte_longer_key_needs_more_text():
    # 데이터가 길고 다양하면 더 긴 키(10바이트)도 복구된다 (열마다 표본이 늘어난다)
    x = _xor_cmd()
    key = b"longsecret"
    ct = _encrypt(LONG_TEXT, key)
    assert "0x" + key.hex() in x.crack_keys(ct, limit=3)


def test_short_input_still_returns_single_byte():
    # MULTIBYTE_MIN 미만이면 다중 바이트 추정은 건너뛰되 1바이트 추정은 그대로 동작
    x = _xor_cmd()
    ct = _encrypt(b"short secret flag text", b"\x5a")
    guesses = x.crack_keys(ct, limit=3)
    assert "0x5a" in guesses
