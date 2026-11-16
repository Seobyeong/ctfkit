"""v0.25 자동 해독 확장: 새 변환 13종, 가벼운 키 추정, 탐색 가지치기, 오탐 방지."""

import base64
import gzip
import zlib

import pytest

from ctfkit import registry
from ctfkit.analysis import letter_ratio
from ctfkit.cli import main
from ctfkit.engine import search
from ctfkit.flags import flag_quality
from ctfkit.registry import TransformError
from ctfkit.transforms import compress

FLAG = b"DH{sample_flag_123}"


def _t(name):
    return registry.get(name)


# --- 정답 벡터 ---

DECODE_VECTORS = [
    ("binary", b"01100110 01101100 01100001 01100111", b"flag"),
    ("bin", b"01100110011011000110000101100111", b"flag"),            # 공백 없음
    ("binary", b"01100110\n01101100\n", b"fl"),                       # 줄바꿈 구분
    ("decimal", b"102 108 97 103", b"flag"),
    ("dec", b"102,108, 97,103", b"flag"),                             # 쉼표 구분
    ("decimal", b"54620 44544", "한글".encode("utf-8")),               # 255 초과는 유니코드 코드포인트
    ("octal", b"146 154 141 147", b"flag"),
    ("a1z26", b"6 12 1 7", b"flag"),
    ("a1z26", b"6-12-1-7", b"flag"),
    ("morse", b"..-. .-.. .- --.", b"flag"),
    ("morse", b".... .. / - .... . .-. .", b"hi there"),              # / 는 단어 구분
    ("morse", b"..-. .-.. .- --. ..--.- .----", b"flag_1"),
    ("reverse", b"}galf{HD", b"DH{flag}"),
    ("rot47", b"u=28", b"Flag"),
    ("atbash", b"Uozt{Svool}", b"Flag{Hello}"),
    ("html", b"&#102;&#108;&#97;&#103;", b"flag"),
    ("html", b"&#x66;&#x6C;ag", b"flag"),                             # 16진 엔티티 + 그대로인 글자
    ("html", b"a &lt; b &amp;&amp; c &gt; d", b"a < b && c > d"),
    ("html", b"&#54620;", "한".encode("utf-8")),
    ("html", b"&nosuch; stays", b"&nosuch; stays"),                   # 모르는 이름은 그대로 둔다
    ("escape", b"\\u0066\\u006c\\x61\\x67", b"flag"),
    ("escape", b"\\ud55c", "한".encode("utf-8")),
    ("escape", b"plain \\x41 text", b"plain A text"),
    ("qp", b"=66=6C=61=67", b"flag"),
    ("qp", b"fl=\r\nag=7B=7D", b"flag{}"),                            # 줄 끝의 = 는 이어 쓰기
    ("gzip", gzip.compress(b"flag{gz}", mtime=0), b"flag{gz}"),
    ("zlib", zlib.compress(b"flag{z}"), b"flag{z}"),
    ("base64", b"-_-_", b"\xfb\xff\xbf"),                             # URL-safe 알파벳
    ("base64", base64.urlsafe_b64encode(b"\xfb\xef\xbeflag").rstrip(b"="), b"\xfb\xef\xbeflag"),
]


@pytest.mark.parametrize("name, data, expected", DECODE_VECTORS)
def test_decode_vectors(name, data, expected):
    assert _t(name).decode(data) == expected


KEYED_VECTORS = [
    # 표준 예: WEAREDISCOVEREDFLEEATONCE 를 레일 3개로
    ("railfence", b"WECRLTEERDSOEEFEAOCAIVDEN", "3", b"WEAREDISCOVEREDFLEEATONCE"),
    ("railfence", b"DasgH{fl_}", "2", None),      # 아래에서 인코딩 결과와 대조
]


def test_railfence_standard_example():
    rail = _t("railfence")
    assert rail.decode(b"WECRLTEERDSOEEFEAOCAIVDEN", "3") == b"WEAREDISCOVEREDFLEEATONCE"
    assert rail.encode(b"WEAREDISCOVEREDFLEEATONCE", "3") == b"WECRLTEERDSOEEFEAOCAIVDEN"


@pytest.mark.parametrize("rails", range(2, 9))
def test_railfence_roundtrip_all_rail_counts(rails):
    rail = _t("railfence")
    for text in (FLAG, b"ab", b"a", b"", b"the quick brown fox"):
        assert rail.decode(rail.encode(text, str(rails)), str(rails)) == text


INVALID = [
    ("binary", b"0110", None),            # 8의 배수가 아님
    ("binary", b"01012", None),
    ("decimal", b"12 ab", None),
    ("decimal", b"99999999", None),       # 유니코드 범위 밖
    ("octal", b"8 9", None),
    ("a1z26", b"0 27", None),
    ("morse", b".-.-.-.-.-.-", None),     # 표에 없는 부호
    ("morse", "한글".encode("utf-8"), None),
    ("gzip", b"not gzip", None),
    ("zlib", b"not zlib", None),
    ("railfence", b"abc", "1"),
    ("railfence", b"abc", "x"),
]


@pytest.mark.parametrize("name, data, key", INVALID)
def test_invalid_input_raises(name, data, key):
    with pytest.raises(TransformError):
        _t(name).decode(data, key)


# --- auto 가 시도하는 조건 (looks_like) ---

@pytest.mark.parametrize("name, data, expected", [
    ("binary", b"01000100 01001000", True),
    ("binary", b"0100", False),                    # 너무 짧음
    ("binary", b"0100010", False),                 # 8의 배수가 아님
    ("decimal", b"68 72 123", True),
    ("decimal", b"68", False),                     # 숫자 하나는 우연일 수 있다
    ("decimal", b"300 400 500", False),            # 0~255 를 벗어남
    ("octal", b"104 110 173", True),
    ("octal", b"108 110 173", False),              # 8 은 8진수가 아님
    ("a1z26", b"6 12 1 7", True),
    ("a1z26", b"6 12 1 77", False),
    ("morse", b"-.. .... -..", True),
    ("morse", b"hello - world", False),
    ("reverse", b"}galf{HD", True),
    ("reverse", b"==QWERTY", True),                # 뒤집힌 base64 패딩
    ("reverse", b"DH{flag}", False),
    ("reverse", b"just some words", False),
    ("rot47", b"swLD2>A=607=28N", True),              # DH{sample_flag}
    ("rot47", b"an ordinary sentence here", False),
    ("rot47", b"QUJDREVGR0g=", False),             # base64 덩어리
    ("atbash", b"Uozt{Svool}", True),
    ("atbash", b"68 72 123 49 50", False),
    ("railfence", b"D{lgHfa}", True),
    ("railfence", b"no braces here", False),
    ("html", b"&#68;&#72;", True),
    ("html", b"R&D department", False),
    ("escape", b"\\u0044\\u0048", True),
    ("escape", b"C:\\users\\name", False),
    ("qp", b"=44=48=7B", True),
    ("qp", b"a=1", False),
    ("qp", b"QUJD=", False),                       # base64 패딩 하나
    ("gzip", gzip.compress(b"x"), True),
    ("gzip", b"plain text", False),
    ("zlib", zlib.compress(b"hello world"), True),
    ("zlib", b"xyzzy plain", False),
    ("base85", base64.b85encode(FLAG), True),      # 결과가 글자면 시도
    ("base85", b"DH{plain_flag_here}", False),     # 평문은 base85 로 풀면 글자가 안 나온다
    ("base85", b"short", False),
])
def test_looks_like(name, data, expected):
    assert _t(name).looks_like(data) is expected


def test_reverse_probe_detects_reversed_hex():
    # 뒤집힌 hex 는 그대로 풀어도 오류가 나지 않아 모양만으로는 알 수 없다. 뒤집어야 글자가 나오는지를 본다
    assert _t("reverse").looks_like(FLAG.hex().encode()[::-1])
    assert not _t("reverse").looks_like(FLAG.hex().encode())


def test_lossy_transforms_are_marked():
    assert _t("morse").lossy and _t("a1z26").lossy
    assert not _t("binary").lossy and not _t("html").lossy


def test_compress_output_is_capped(monkeypatch):
    # 압축 폭탄: 작은 입력이 아주 크게 풀리면 메모리를 다 쓰기 전에 멈춘다
    monkeypatch.setattr(compress, "MAX_OUTPUT", 1000)
    bomb = zlib.compress(b"\x00" * 100_000)
    with pytest.raises(TransformError):
        _t("zlib").decode(bomb)
    assert _t("zlib").decode(zlib.compress(b"\x00" * 500)) == b"\x00" * 500


# --- auto 로 한 번에 ---

def _morse(text):
    table = {"d": "-..", "h": "....", "f": "..-.", "l": ".-..", "a": ".-", "g": "--."}
    return " ".join(table[c] for c in text).encode()


@pytest.mark.parametrize("title, data", [
    ("2진수", " ".join(f"{b:08b}" for b in FLAG).encode()),
    ("10진 코드", " ".join(str(b) for b in FLAG).encode()),
    ("8진 코드", " ".join(f"{b:o}" for b in FLAG).encode()),
    ("뒤집기", FLAG[::-1]),
    ("뒤집힌 base64", base64.b64encode(FLAG)[::-1]),
    ("뒤집힌 hex", FLAG.hex().encode()[::-1]),
    ("ROT47", _t("rot47").encode(FLAG)),
    ("아트배시", _t("atbash").encode(FLAG)),
    ("레일 펜스 3", _t("railfence").encode(FLAG, "3")),
    ("레일 펜스 5", _t("railfence").encode(FLAG, "5")),
    ("HTML 엔티티", "".join(f"&#{b};" for b in FLAG).encode()),
    ("유니코드 이스케이프", "".join(f"\\u{b:04x}" for b in FLAG).encode()),
    ("quoted-printable", "".join(f"={b:02X}" for b in FLAG).encode()),
    ("gzip + base64", base64.b64encode(gzip.compress(FLAG, mtime=0))),
    ("zlib + hex", zlib.compress(FLAG).hex().encode()),
    ("URL-safe base64", base64.urlsafe_b64encode(b"\xfb\xef\xbe" + FLAG)),
    ("base85", base64.b85encode(FLAG)),
    ("2진수 > base64 > hex", " ".join(f"{b:08b}" for b in FLAG).encode().hex().encode()
     and base64.b64encode(" ".join(f"{b:08b}" for b in FLAG).encode()).hex().encode()),
])
def test_auto_solves(title, data):
    results = search(data)
    assert results and results[0].flag == FLAG, title


def test_auto_reads_morse():
    results = search(_morse("dhflag"))
    assert any(r.data == b"dhflag" for r in results[:3])


# --- 오탐 방지: 플래그가 없는 입력에서 플래그를 지어내지 않는다 ---

@pytest.mark.parametrize("data", [
    b"hello world",
    base64.b64encode(b"hello world"),
    base64.b64encode(b"myctf{custom_format}"),     # 기본 형식이 아닌 플래그는 --flag 를 줘야 한다
    b"the quick brown fox jumps over the lazy dog",
    b"68 72 101 108 108 111",
    b"a1b2c3d4e5f60718293a4b5c6d7e8f90",
    b"just {some} braces {in} text",
])
def test_no_flag_is_invented(data):
    results = search(data)
    assert not results or results[0].flag is None


def test_cli_exit_code_stays_not_found_for_plain_text(capsys):
    assert main(["-q", "auto", base64.b64encode(b"hello world").decode()]) == 1


@pytest.mark.parametrize("flag, low, high", [
    (b"DH{clean_flag_123}", 0.99, 1.0),
    (b"flag{%W{*!n}", 0.0, 0.5),
    (None, 0.0, 0.0),
])
def test_flag_quality(flag, low, high):
    assert low <= flag_quality(flag) <= high


def test_cleaner_flag_wins_a_tie():
    # 같은 단계에서 플래그 후보가 둘 나오면 영숫자·밑줄 위주인 쪽이 앞에 온다
    data = base64.b32encode(_t("url").encode(_t("rot13").encode(b"flag{a b/c}")))
    assert search(data)[0].flag == b"flag{a b/c}"


# --- 탐색 가지치기와 속도 ---

def test_same_keyed_cipher_is_not_chained():
    results = search(_t("railfence").encode(b"no flag in {this} text at all", "3"))
    for result in results:
        names = [s.transform for s in result.steps]
        assert not any(a == b and registry.get(a).needs_key for a, b in zip(names, names[1:])), names


def test_xor_is_not_tried_after_a_text_cipher():
    results = search(_t("railfence").encode(b"no flag in {this} text at all", "3"))
    for result in results:
        names = [s.transform for s in result.steps]
        assert not any(registry.get(a).text_cipher and b == "xor" for a, b in zip(names, names[1:])), names


def test_letter_ratio_gates_alphabet_ciphers():
    assert letter_ratio(b"\\u0044\\u0048") < 0.5 < letter_ratio(b"Flag{Hello}")
    escapes = "".join(f"\\u{b:04x}" for b in FLAG).encode()
    assert not _t("caesar").looks_like(escapes)
    assert not _t("vigenere").looks_like(escapes * 3)
    assert _t("caesar").looks_like(b"Iodj{Khoor}")


def test_vigenere_fast_guess_and_thorough_crack():
    v = _t("vigenere")
    text = (b"it was a bright cold day in april and the clocks were striking thirteen winston smith his chin "
            b"nuzzled into his breast in an effort to escape the vile wind slipped quickly through the glass doors")
    ct = v.encode(text, "LEMON")
    assert v.guess_keys(ct)[0] == "LEMON"      # auto 가 쓰는 빠른 추정 (빈도 분석만)
    assert v.crack_keys(ct)[0] == "LEMON"      # crack 이 쓰는 철저한 추정 (언덕 오르기)


def test_long_unsolvable_input_finishes_quickly():
    import time

    # v0.24 에서는 이런 입력에 수십 초가 걸렸다 (모든 후보에 비즈네르 언덕 오르기를 돌렸다)
    data = ("".join(f"\\u{b:04x}" for b in b"nothing to find in this long piece of text " * 6)).encode()
    start = time.perf_counter()
    search(data)
    assert time.perf_counter() - start < 10
