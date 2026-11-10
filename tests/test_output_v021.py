"""v0.21 읽기 토큰 줄이기: --quiet 면 답만 출력한다. 기본 출력은 그대로다."""

import base64
import hashlib
import io
import json
import zipfile

import pytest

from ctfkit import console
from ctfkit.cli import main


@pytest.fixture(autouse=True)
def _reset_quiet():
    console.QUIET = False
    yield
    console.QUIET = False


def _run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


# --- auto ---

TWO_LAYERS = base64.b64encode(b"DH{quiet_auto}".hex().encode()).decode()


def test_auto_quiet_prints_only_flag(capsys):
    code, out, err = _run(capsys, "-q", "auto", TWO_LAYERS)
    assert code == 0
    assert out == "DH{quiet_auto}\n"
    assert err == ""


def test_auto_default_still_shows_path(capsys):
    code, out, _ = _run(capsys, "auto", TWO_LAYERS)
    assert code == 0
    assert "[1] base64" in out and "[2] hex" in out
    assert out.splitlines()[-1] == "DH{quiet_auto}"


def test_auto_quiet_without_flag_prints_candidates_only(capsys):
    code, out, _ = _run(capsys, "-q", "auto", base64.b64encode(b"just some plain words").decode(), "-n", "1")
    assert code == 1
    assert out.splitlines() == ["just some plain words"]


# --- crack ---

def test_crack_quiet_is_key_tab_result(capsys):
    code, out, _ = _run(capsys, "-q", "crack", "caesar", "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj", "-n", "1")
    assert code == 0
    assert out == "3\tThe quick brown fox jumps over the lazy dog\n"


def test_crack_default_keeps_table_header(capsys):
    _, out, _ = _run(capsys, "crack", "caesar", "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj", "-n", "1")
    assert out.splitlines()[0].split() == ["key", "score", "result"]


# --- rsa ---

RSA_N = "1208925852309707152975447"
RSA_C = "298898839777870285982038"


def test_rsa_quiet_prints_plaintext_only(capsys):
    code, out, err = _run(capsys, "-q", "rsa", "decrypt", "-n", RSA_N, "-e", "65537", "-c", RSA_C)
    assert code == 0
    assert out == "flag{rsa}\n"
    assert err == ""


def test_rsa_default_shows_all_forms(capsys):
    _, out, _ = _run(capsys, "rsa", "decrypt", "-n", RSA_N, "-e", "65537", "-c", RSA_C)
    assert "m (int) = " in out and "m (bytes) = flag{rsa}" in out


# --- hash ---

def test_hash_crack_quiet_prints_word_only(tmp_path, capsys):
    words = tmp_path / "w.txt"
    words.write_text("apple\nbanana\ncherry\n", encoding="ascii")
    digest = hashlib.md5(b"banana").hexdigest()
    code, out, _ = _run(capsys, "-q", "hash", "crack", digest, "-w", str(words))
    assert code == 0
    assert out == "banana\n"


def test_hash_id_quiet_prints_names_only(capsys):
    _, out, _ = _run(capsys, "-q", "hash", "id", hashlib.md5(b"x").hexdigest())
    assert out.startswith("md5")
    assert "가능한" not in out


# --- jwt ---

JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJhZG1pbiI6ZmFsc2V9.7Mc4Ujc5fz2145BmF6Q2f-zwslS_RkT5Kn_2x6YxWxg"


def test_jwt_decode_quiet_is_two_json_lines(capsys):
    code, out, _ = _run(capsys, "-q", "jwt", "decode", JWT)
    assert code == 0
    header, payload = out.splitlines()
    assert json.loads(header) == {"alg": "HS256", "typ": "JWT"}
    assert json.loads(payload) == {"user": "guest", "admin": False}


def test_jwt_crack_quiet_prints_secret_only(tmp_path, capsys):
    words = tmp_path / "w.txt"
    words.write_text("password\nsecret\nadmin\n", encoding="ascii")
    code, out, _ = _run(capsys, "-q", "jwt", "crack", JWT, "-w", str(words))
    assert code == 0
    assert out == "secret\n"


# --- forensic ---

def _png_with_zip(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", "hello")
    path = tmp_path / "pic.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64 + buf.getvalue())
    return str(path)


def test_carve_quiet_is_offset_and_type(tmp_path, capsys):
    code, out, _ = _run(capsys, "-q", "forensic", "carve", _png_with_zip(tmp_path))
    assert code == 0
    assert out.splitlines() == ["0x48 ZIP"]


def test_carve_default_keeps_header(tmp_path, capsys):
    _, out, _ = _run(capsys, "forensic", "carve", _png_with_zip(tmp_path))
    assert out.startswith("[+] 숨은 파일 시그니처 1개:")


def test_zip_quiet_drops_table_header(tmp_path, capsys):
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("a.txt", "hello")
    _, out, _ = _run(capsys, "-q", "forensic", "zip", str(path))
    assert len(out.splitlines()) == 1 and "a.txt" in out


def _many_strings(tmp_path, count):
    path = tmp_path / "many.bin"
    path.write_bytes(b"\x00".join(f"string_number_{i:04d}".encode() for i in range(count)))
    return str(path)


def test_strings_default_limit_caps_output(tmp_path, capsys):
    _, out, err = _run(capsys, "forensic", "strings", _many_strings(tmp_path, 300))
    assert len(out.splitlines()) == console.DEFAULT_LIMIT
    assert "100개 더 있음" in err


def test_strings_limit_zero_shows_all(tmp_path, capsys):
    _, out, err = _run(capsys, "forensic", "strings", _many_strings(tmp_path, 300), "--limit", "0")
    assert len(out.splitlines()) == 300
    assert err == ""


def test_strings_quiet_still_reports_truncation(tmp_path, capsys):
    _, out, err = _run(capsys, "-q", "forensic", "strings", _many_strings(tmp_path, 300))
    assert len(out.splitlines()) == console.DEFAULT_LIMIT
    assert err == "... +100\n"
