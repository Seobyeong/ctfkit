import pytest

from ctfkit import registry
from ctfkit.registry import Transform, TransformError

TRANSFORMS = registry.all_transforms()

# 모든 변환이 공통으로 통과해야 하는 왕복 테스트용 입력
SAMPLES = [
    b"flag{hello}",
    b"",
    b"\x00\xff\x10binary",
    "한글 플래그".encode("utf-8"),
]


@pytest.mark.parametrize("sample", SAMPLES)
@pytest.mark.parametrize("t", TRANSFORMS, ids=lambda t: t.name)
def test_roundtrip(t, sample):
    # 새 변환을 추가하면 이 테스트가 자동으로 적용된다
    key = t.example_key if t.needs_key else None
    assert t.decode(t.encode(sample, key), key) == sample


# 변환별 정답 벡터: (변환 이름, 입력, 기대 출력)
DECODE_VECTORS = [
    ("base64", b"ZmxhZ3toZWxsb30=", b"flag{hello}"),
    ("b64", b"ZmxhZ3toZWxsb30", b"flag{hello}"),   # 패딩 누락
    ("base64", b"ZmxhZ3toZWxsb30=\n", b"flag{hello}"),
    ("hex", b"666c6167", b"flag"),
    ("hex", b"0x666C6167", b"flag"),
    ("hex", b"66 6c 61 67", b"flag"),
    ("url", b"flag%7Bhi%7D", b"flag{hi}"),
    ("url", b"a+b%20c", b"a b c"),
    ("rot13", b"synt{uryyb_JBEYQ}", b"flag{hello_WORLD}"),
    ("base32", b"MZWGCZ33NBSWY3DPPU======", b"flag{hello}"),
    ("b32", b"mzwgcz33nbswy3dppu", b"flag{hello}"),   # 소문자 + 패딩 누락
]


@pytest.mark.parametrize("name, data, expected", DECODE_VECTORS)
def test_decode_vectors(name, data, expected):
    assert registry.get(name).decode(data) == expected


# 키가 필요한 변환의 정답 벡터: (변환 이름, 입력, 키, 기대 출력)
KEYED_VECTORS = [
    ("xor", b"FLAG", "0x20", b"flag"),
    ("xor", b"\x07\x0e\x00\x05", "0x6162", b"flag"),   # 2바이트 반복 키 "ab"
    ("xor", b"\x07\x0e\x00\x05", "ab", b"flag"),       # 문자열 키
]


@pytest.mark.parametrize("name, data, key, expected", KEYED_VECTORS)
def test_keyed_vectors(name, data, key, expected):
    assert registry.get(name).decode(data, key) == expected


INVALID_INPUTS = [
    ("base64", b"!!!", None),
    ("base64", b"abcde", None),   # 길이가 4로 나눠 1이 남으면 복구 불가
    ("hex", b"zz", None),
    ("hex", b"abc", None),        # 홀수 길이
    ("hex", "가".encode("utf-8"), None),
    ("base32", b"18!!", None),
    ("xor", b"flag", ""),         # 빈 키
    ("xor", b"flag", "0x2"),      # 홀수 자리 16진수 키
    ("xor", b"flag", "0xzz"),
]


@pytest.mark.parametrize("name, data, key", INVALID_INPUTS)
def test_invalid_input_raises_transform_error(name, data, key):
    with pytest.raises(TransformError):
        registry.get(name).decode(data, key)


@pytest.mark.parametrize("name, data, expected", [
    ("base64", b"ZmxhZw==", True),
    ("base64", b"flag{x}", False),
    ("hex", b"666c6167", True),
    ("hex", b"flag", False),
    ("url", b"flag%7Bhi%7D", True),
    ("url", b"flag{hi}", False),
    ("base32", b"MZWGCZ33", True),
    ("base32", b"flag{hi}", False),
])
def test_looks_like(name, data, expected):
    assert registry.get(name).looks_like(data) is expected


def test_unknown_transform():
    with pytest.raises(TransformError):
        registry.get("no-such-transform")


def test_duplicate_name_is_rejected():
    class Dup(Transform):
        name = "base64"

    with pytest.raises(ValueError):
        registry.register(Dup)
