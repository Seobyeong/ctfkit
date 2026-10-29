"""hash 명령 테스트."""

import hashlib

from ctfkit.cli import main
from ctfkit.commands.hashes import identify

MD5_FLAG = hashlib.md5(b"flag").hexdigest()


def test_identify_md5_length():
    assert "md5" in identify("5f4dcc3b5aa765d61d8327deb882cf99")


def test_identify_sha256_length():
    assert "sha256" in identify("a" * 64)


def test_identify_non_hex():
    assert identify("not-a-hash!") == []


def test_id_command(capsys):
    assert main(["hash", "id", "5f4dcc3b5aa765d61d8327deb882cf99"]) == 0
    assert "md5" in capsys.readouterr().out


def test_id_unknown_length(capsys):
    assert main(["hash", "id", "abc"]) == 1
    assert "판별 실패" in capsys.readouterr().out


def test_sum_matches_hashlib(capsys):
    assert main(["hash", "sum", "sha256", "flag"]) == 0
    assert capsys.readouterr().out.strip() == hashlib.sha256(b"flag").hexdigest()


def test_sum_unknown_algo(capsys):
    assert main(["hash", "sum", "nope", "x"]) == 1
    assert "오류" in capsys.readouterr().err


def test_crack_finds_word(tmp_path, capsys):
    words = tmp_path / "words.txt"
    words.write_text("foo\nbar\nflag\nbaz\n")
    assert main(["hash", "crack", MD5_FLAG, "--words", str(words)]) == 0
    assert "flag" in capsys.readouterr().out


def test_crack_not_found(tmp_path, capsys):
    words = tmp_path / "words.txt"
    words.write_text("foo\nbar\n")
    assert main(["hash", "crack", MD5_FLAG, "--words", str(words), "--algo", "md5"]) == 1
    assert "찾지 못함" in capsys.readouterr().err


def test_crack_explicit_algo(tmp_path, capsys):
    digest = hashlib.sha1(b"secret").hexdigest()
    words = tmp_path / "words.txt"
    words.write_text("nope\nsecret\n")
    assert main(["hash", "crack", digest, "--words", str(words), "--algo", "sha1"]) == 0
    assert "secret" in capsys.readouterr().out


def test_hmac_matches_stdlib(capsys):
    import hmac
    assert main(["hash", "hmac", "sha256", "msg", "--key", "k"]) == 0
    expected = hmac.new(b"k", b"msg", "sha256").hexdigest()
    assert capsys.readouterr().out.strip() == expected


def test_hmac_hex_key(capsys):
    import hmac
    assert main(["hash", "hmac", "sha1", "msg", "--key", "0x4142"]) == 0
    expected = hmac.new(b"AB", b"msg", "sha1").hexdigest()
    assert capsys.readouterr().out.strip() == expected
