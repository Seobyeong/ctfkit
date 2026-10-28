from ctfkit import analysis

ENGLISH = b"It was a bright cold day in April, and the clocks were striking thirteen."
RANDOM_LETTERS = b"qzxjkvqzxwjqkzvxqjzkwvxqzjkvqxzj"


def test_printable_ratio():
    assert analysis.printable_ratio(b"abc") == 1.0
    assert analysis.printable_ratio(b"\x00\x01ab") == 0.5
    assert analysis.printable_ratio(b"") == 0.0


def test_letter_counts_ignores_case():
    counts = analysis.letter_counts(b"aA!z")
    assert counts[0] == 2
    assert counts[25] == 1
    assert sum(counts) == 3


def test_chi_squared_prefers_english():
    assert analysis.chi_squared(ENGLISH) < analysis.chi_squared(RANDOM_LETTERS)
    assert analysis.chi_squared(b"1234") == float("inf")


def test_index_of_coincidence():
    assert analysis.index_of_coincidence(b"aaaa") == 1.0
    assert analysis.index_of_coincidence(b"a") == 0.0
    # 영어 문장은 무작위(약 0.038)보다 높다
    assert analysis.index_of_coincidence(ENGLISH) > 0.05


def test_english_score_and_text_score():
    assert analysis.english_score(ENGLISH) > analysis.english_score(RANDOM_LETTERS)
    assert analysis.english_score(b"") == 0.0
    assert analysis.text_score(ENGLISH) > analysis.text_score(bytes(range(256)))
    assert analysis.text_score(b"") == 0.0


def test_looks_encoded():
    assert analysis.looks_encoded(b"ZmxhZ3toZWxsb30=")
    assert analysis.looks_encoded(b"666c61677b7d")
    assert not analysis.looks_encoded(b"hello world")
    assert not analysis.looks_encoded(b"short")
