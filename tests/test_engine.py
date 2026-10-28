"""auto 엔진 회귀 테스트: 여러 겹으로 감싼 플래그를 실제로 찾아내는지 확인한다."""

import pytest

from ctfkit import registry
from ctfkit.engine import search
from ctfkit.flags import compile_flag_pattern, find_flag

def wrap(data, *chain):
    """평문에 변환을 차례로 적용해 문제를 만든다. 키가 있으면 (이름, 키) 튜플."""
    for item in chain:
        name, key = item if isinstance(item, tuple) else (item, None)
        data = registry.get(name).encode(data, key)
    return data


CHALLENGES = [
    # (설명, 평문, 적용한 변환들, 기대하는 풀이 경로)
    ("3겹 인코딩", b"DH{auto_works}", ["base64", "hex", "base64"],
     ["base64", "hex", "base64"]),
    ("5겹 인코딩", b"DH{deep_layers}", ["base64", "base32", "hex", "base64", "hex"],
     ["hex", "base64", "hex", "base32", "base64"]),
    ("rot13 + url + base32", b"flag{a b/c}", ["rot13", "url", "base32"],
     ["base32", "url", "rot13"]),
]


@pytest.mark.parametrize("plain, chain, expected_path",
                         [c[1:] for c in CHALLENGES], ids=[c[0] for c in CHALLENGES])
def test_finds_flag(plain, chain, expected_path):
    results = search(wrap(plain, *chain))
    best = results[0]
    assert best.flag == find_flag(plain, compile_flag_pattern())
    assert [step.transform for step in best.steps] == expected_path


def test_without_flag_plaintext_ranks_first():
    plain = b"just a normal sentence without anything special"
    results = search(wrap(plain, "base64", "hex"))
    assert results[0].flag is None
    assert results[0].data == plain


def test_custom_flag_pattern():
    data = wrap(b"myctf{custom_format}", "base64")
    assert search(data)[0].flag is None
    assert search(data, flag_pattern=r"myctf\{.*?\}")[0].flag == b"myctf{custom_format}"


def test_invalid_flag_pattern():
    with pytest.raises(ValueError):
        search(b"abc", flag_pattern="(")


def test_depth_limit():
    data = wrap(b"DH{deep}", "base64", "hex", "base64")
    assert search(data, depth=2)[0].flag is None
    assert search(data, depth=3)[0].flag == b"DH{deep}"
