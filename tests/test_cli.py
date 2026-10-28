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


def test_stdin_input(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"666c6167\r\n")))
    assert main(["codec", "decode", "hex"]) == 0
    assert capsys.readouterr().out == "flag\n"
