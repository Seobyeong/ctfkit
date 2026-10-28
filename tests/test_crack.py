"""키가 필요한 변환들의 guess_keys (키 추정) 테스트."""

from ctfkit import registry
from ctfkit.flags import compile_flag_pattern, find_flag

PARAGRAPH = (
    b"It was a bright cold day in April, and the clocks were striking thirteen. "
    b"Winston Smith, his chin nuzzled into his breast in an effort to escape the vile wind, "
    b"slipped quickly through the glass doors of Victory Mansions. The flag is flag{vigenere_is_fun}"
)


def _encrypt(name, data, key):
    return registry.get(name).encode(data, key)


def test_caesar_guess():
    ct = _encrypt("caesar", PARAGRAPH, "11")
    assert registry.get("caesar").guess_keys(ct)[0] == "11"


def test_caesar_guess_short_flag_within_candidates():
    # 짧은 문자열은 통계가 불안정하므로 1등이 아니어도 후보 안에만 있으면 된다
    ct = _encrypt("caesar", b"DH{simple_caesar_shift}", "7")
    assert "7" in registry.get("caesar").guess_keys(ct)


def test_caesar_no_letters():
    assert registry.get("caesar").guess_keys(b"1234") == []


def test_vigenere_guess():
    ct = _encrypt("vigenere", PARAGRAPH, "LEMON")
    assert registry.get("vigenere").guess_keys(ct)[0] == "LEMON"


def test_vigenere_too_short():
    assert registry.get("vigenere").guess_keys(b"abc def") == []


def test_xor_single_byte_statistical():
    ct = _encrypt("xor", b"the secret flag is somewhere in this sentence", "0x5a")
    assert registry.get("xor").guess_keys(ct)[0] == "0x5a"


def test_xor_known_plaintext_multi_byte():
    # 플래그 접두사 "DH{" 를 알면 여러 바이트 키도 바로 구할 수 있다
    ct = _encrypt("xor", b"DH{multi_byte_xor_key}", "0x1337")
    assert registry.get("xor").guess_keys(ct)[0] == "0x1337"


def test_xor_known_plaintext_result_has_flag():
    ct = _encrypt("xor", b"flag{known_plaintext}", "0xdeadbe")
    xor = registry.get("xor")
    pattern = compile_flag_pattern()
    assert any(find_flag(xor.decode(ct, k), pattern) for k in xor.guess_keys(ct))


def test_xor_empty():
    assert registry.get("xor").guess_keys(b"") == []


def test_keyless_transform_has_no_guess():
    assert registry.get("base64").guess_keys(b"ZmxhZw==") == []
