import io
import sys

from ctfkit.cli import main


def test_list(capsys):
    assert main(["codec", "list"]) == 0
    out = capsys.readouterr().out
    assert "base64" in out
    assert "hex" in out


def test_decode(capsys):
    assert main(["codec", "decode", "base64", "ZmxhZ3toZWxsb30="]) == 0
    assert capsys.readouterr().out == "flag{hello}\n"


def test_encode(capsys):
    assert main(["codec", "encode", "hex", "flag"]) == 0
    assert capsys.readouterr().out == "666c6167\n"


def test_alias(capsys):
    assert main(["codec", "decode", "b64", "ZmxhZw=="]) == 0
    assert capsys.readouterr().out == "flag\n"


def test_invalid_input_prints_error(capsys):
    assert main(["codec", "decode", "base64", "!!!"]) == 1
    assert "오류" in capsys.readouterr().err


def test_unknown_transform(capsys):
    assert main(["codec", "decode", "nope", "abc"]) == 1
    assert "알 수 없는 변환" in capsys.readouterr().err


def test_binary_output_shown_as_hex(capsys):
    assert main(["codec", "decode", "hex", "00ff"]) == 0
    assert capsys.readouterr().out == "00ff\n"


def test_file_input(tmp_path, capsys):
    path = tmp_path / "input.txt"
    path.write_bytes(b"ZmxhZw==")
    assert main(["codec", "decode", "base64", "--file", str(path)]) == 0
    assert capsys.readouterr().out == "flag\n"


def test_missing_file(capsys):
    assert main(["codec", "decode", "base64", "--file", "no/such/file"]) == 1
    assert "오류" in capsys.readouterr().err


def test_keyed_transform(capsys):
    assert main(["codec", "decode", "xor", "FLAG", "--key", "0x20"]) == 0
    assert capsys.readouterr().out == "flag\n"


def test_missing_key(capsys):
    assert main(["codec", "decode", "xor", "FLAG"]) == 1
    assert "--key" in capsys.readouterr().err


def test_auto_finds_flag(capsys):
    # "DH{auto}" -> base64 -> hex
    assert main(["auto", "52456837595856306233303d"]) == 0
    out = capsys.readouterr().out
    assert "[+]" in out
    assert out.strip().endswith("DH{auto}")


def test_auto_without_flag(capsys):
    assert main(["auto", "aGVsbG8gd29ybGQ=", "--top", "1"]) == 1
    out = capsys.readouterr().out
    assert "[-]" in out
    assert "hello world" in out


def test_auto_invalid_options(capsys):
    assert main(["auto", "abc", "--flag", "("]) == 1
    assert main(["auto", "abc", "--depth", "0"]) == 1
    assert "오류" in capsys.readouterr().err


def test_crack(capsys):
    assert main(["crack", "caesar", "GK{fdhvdu}"]) == 0
    out = capsys.readouterr().out
    assert "DH{caesar}" in out
    assert "<- flag" in out


def test_crack_keyless_transform(capsys):
    assert main(["crack", "base64", "ZmxhZw=="]) == 1
    assert "키가 없는 변환" in capsys.readouterr().err


def test_crack_cannot_guess(capsys):
    assert main(["crack", "vigenere", "short"]) == 1
    assert "추정할 수 없습니다" in capsys.readouterr().err


def test_non_utf8_console_does_not_crash(monkeypatch):
    # 영어 Windows 에서 파이프로 출력할 때처럼 한글을 표현할 수 없는 인코딩
    buffer = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(buffer, encoding="cp1252"))
    assert main(["codec", "list"]) == 0
    sys.stdout.flush()
    assert b"base64" in buffer.getvalue()


def test_stdin_input(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"666c6167\r\n")))
    assert main(["codec", "decode", "hex"]) == 0
    assert capsys.readouterr().out == "flag\n"
