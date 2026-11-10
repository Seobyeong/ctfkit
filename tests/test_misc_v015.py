"""v0.15 misc 테스트: base58/base85 변환, base 진법 명령, web diff."""

import base64

import pytest

from ctfkit import registry
from ctfkit.cli import main
from ctfkit.commands import web


# --- base58 / base85 변환 ---

def test_base58_roundtrip():
    t = registry.get("base58")
    enc = t.encode(b"Hello, CTF!")
    assert t.decode(enc) == b"Hello, CTF!"


def test_base58_leading_zero_bytes():
    # 맨 앞 0x00 바이트는 '1' 로 보존돼야 한다 (비트코인 주소 규칙)
    t = registry.get("base58")
    enc = t.encode(b"\x00\x00abc")
    assert enc.startswith(b"11")
    assert t.decode(enc) == b"\x00\x00abc"


def test_base58_known_vector():
    # "hello world" 의 Base58 은 널리 알려진 값
    t = registry.get("base58")
    assert t.encode(b"hello world") == b"StV1DL6CwTryKyV"
    assert t.decode(b"StV1DL6CwTryKyV") == b"hello world"


def test_base58_invalid_char():
    t = registry.get("base58")
    with pytest.raises(registry.TransformError):
        t.decode(b"0OIl")          # 알파벳에 없는 글자


def test_base85_roundtrip():
    t = registry.get("base85")
    assert t.decode(t.encode(b"ctfkit base85")) == b"ctfkit base85"
    # Python 표준 b85 와 호환
    assert t.decode(base64.b85encode(b"xyz")) == b"xyz"


def test_ascii85_roundtrip_and_adobe():
    t = registry.get("ascii85")
    assert t.decode(t.encode(b"adobe!")) == b"adobe!"
    assert t.decode(b"<~" + base64.a85encode(b"wrapped") + b"~>") == b"wrapped"


def test_base85_excluded_from_auto():
    # base85/ascii85 는 auto 오염을 막으려 looks_like=False
    assert registry.get("base85").looks_like(b"anything") is False
    assert registry.get("ascii85").looks_like(b"anything") is False


def test_codec_base58_cli(capsys):
    assert main(["codec", "encode", "base58", "hi"]) == 0
    enc = capsys.readouterr().out.strip()
    assert main(["codec", "decode", "base58", enc]) == 0
    assert capsys.readouterr().out.strip() == "hi"


# --- base 진법 변환 ---

def test_base_all_forms(capsys):
    assert main(["base", "255"]) == 0
    out = capsys.readouterr().out
    assert "11111111" in out and "377" in out and "ff" in out


def test_base_hex_prefix_to_bin(capsys):
    assert main(["base", "0xff", "--to", "2"]) == 0
    assert capsys.readouterr().out.strip() == "11111111"


def test_base_from_octal(capsys):
    assert main(["base", "777", "--from", "8", "--to", "10"]) == 0
    assert capsys.readouterr().out.strip() == "511"


def test_base_negative(capsys):
    assert main(["base", "-16", "--to", "16"]) == 0
    assert capsys.readouterr().out.strip() == "-10"


def test_base_invalid(capsys):
    assert main(["base", "xyz"]) == 1
    assert "해석할 수 없습니다" in capsys.readouterr().err


def test_base_bad_to(capsys):
    assert main(["base", "10", "--to", "7"]) == 1
    assert "2, 8, 10, 16" in capsys.readouterr().err


# --- web diff (네트워크 없이 _do_request 를 가짜로 대체) ---

def test_web_diff_reports_differences(capsys, monkeypatch):
    responses = iter([(200, b"line1\nline2\n"), (403, b"line1\nCHANGED\nline3\n")])
    monkeypatch.setattr(web, "_do_request", lambda *a, **k: next(responses))
    assert main(["web", "diff", "http://localhost/a", "http://localhost/b"]) == 0
    out = capsys.readouterr().out
    assert "200 vs 403" in out
    assert "다름" in out
    assert "CHANGED" in out


def test_web_diff_identical(capsys, monkeypatch):
    monkeypatch.setattr(web, "_do_request", lambda *a, **k: (200, b"same body"))
    assert main(["web", "diff", "http://localhost/a", "http://localhost/b"]) == 0
    out = capsys.readouterr().out
    assert "동일" in out


def test_web_diff_blocks_disallowed_host(capsys):
    assert main(["web", "diff", "http://evil.example/a", "http://localhost/b"]) == 1
    assert "허용되지 않은 호스트" in capsys.readouterr().err
