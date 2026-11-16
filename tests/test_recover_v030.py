"""v0.30 실전 기록 2: hex 로 적고 바이트마다 128 을 더해 숨긴 이미지.

148KB 짜리 hex 글자 파일이었다. triage 는 4KB 이하의 글자만 auto 로 해독해 보고, auto 는 글자 플래그만 찾으므로
플래그가 그림으로 들어 있는 이미지는 찾을 방법이 없었다. 파일 머리(매직 바이트)로 되살리는 recover 를 만들었다.
아래 파일은 실제 문제가 아니라 같은 형태로 직접 만든 예제다.
"""

import base64
import io
import random
import zipfile

import pytest

from ctfkit import console, recover
from ctfkit.cli import main

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + bytes(range(256)) * 4
PDF = b"%PDF-1.4\n" + b"some pdf body " * 50
ZIP_HEAD = b"PK\x03\x04" + bytes(300)


@pytest.fixture(autouse=True)
def _reset_quiet():
    console.QUIET = False
    yield
    console.QUIET = False


def _run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def _add(data: bytes, d: int) -> bytes:
    return bytes((b + d) % 256 for b in data)


@pytest.mark.parametrize("encoded, steps", [
    (_add(PNG, 128).hex().upper().encode(), ["hex", "xor 0x80 (= 바이트 ±128)"]),
    (PNG.hex().encode(), ["hex"]),
    (base64.b64encode(PDF), ["base64"]),
    (bytes(b ^ 0x37 for b in PNG), ["xor 0x37"]),
    (_add(PDF, 13), ["바이트마다 -13 (mod 256)"]),
    (PNG[::-1], ["뒤집기"]),
    (_add(ZIP_HEAD, 3).hex().encode(), ["hex", "바이트마다 -3 (mod 256)"]),
])
def test_recovers(encoded, steps):
    result = recover.recover(encoded)
    assert result is not None and result.steps == steps
    assert result.data in (PNG, PDF, ZIP_HEAD)


def test_hex_with_whitespace_and_prefix():
    text = b"0x" + PNG.hex().encode()
    assert recover.recover(text).data == PNG
    spaced = b"\n".join(PNG.hex().encode()[i:i + 64] for i in range(0, len(PNG) * 2, 64))
    assert recover.recover(spaced).data == PNG


def test_already_known_file_is_not_recovered():
    assert recover.recover(PNG) is None


@pytest.mark.parametrize("seed", range(20))
def test_random_data_is_not_recovered(seed):
    rng = random.Random(seed)
    blob = bytes(rng.randrange(256) for _ in range(2000))
    assert recover.recover(blob) is None
    assert recover.recover(blob.hex().encode()) is None
    assert recover.recover(base64.b64encode(blob)) is None


def test_plain_text_is_not_recovered():
    assert recover.recover(b"hello world, this is just a note\n" * 10) is None


def test_ext():
    assert recover.ext_for("PNG 이미지") == ".png"
    assert recover.ext_for("ZIP (또는 docx/jar/apk 등)") == ".zip"
    assert recover.ext_for("모르는 형식") == ".bin"


def test_triage_reports_recovery(tmp_path, capsys):
    path = tmp_path / "encfile"
    path.write_bytes(_add(PNG, 128).hex().upper().encode())
    code, out, _ = _run(capsys, "triage", str(path), "--no-external")
    assert code == 1
    assert "복원: hex → xor 0x80 (= 바이트 ±128) → PNG 이미지" in out
    assert "forensic recover" in out


def test_triage_finds_flag_inside_recovered_file(tmp_path, capsys):
    path = tmp_path / "enc"
    path.write_bytes(bytes(b ^ 0x55 for b in PNG + b"tEXtDH{recovered_text}"))
    code, out, _ = _run(capsys, "triage", str(path), "--no-external")
    assert code == 0 and "DH{recovered_text}" in out and "복원한 PNG" in out


def test_forensic_recover_writes_file(tmp_path, capsys):
    src = tmp_path / "enc.txt"
    src.write_bytes(_add(PNG, 128).hex().encode())
    out_path = tmp_path / "out.png"
    code, out, _ = _run(capsys, "forensic", "recover", str(src), "-o", str(out_path))
    assert code == 0 and "PNG 이미지" in out
    assert out_path.read_bytes() == PNG


def test_forensic_recover_fails_cleanly(tmp_path, capsys):
    src = tmp_path / "x.txt"
    src.write_bytes(b"nothing hidden here at all\n")
    code, out, err = _run(capsys, "forensic", "recover", str(src))
    assert code == 1 and out == "" and "되살리지 못했습니다" in err


def test_start_saves_recovered_file_and_says_to_open_it(tmp_path, capsys):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("encfile", _add(PNG, 128).hex().upper())
    archive = tmp_path / "prob.zip"
    archive.write_bytes(buf.getvalue())
    code, out, _ = _run(capsys, "start", str(archive), "--root", str(tmp_path / "ws"), "--no-external")
    assert code == 1
    saved = tmp_path / "ws" / "prob" / "extracted" / "prob.zip" / "encfile.recovered.png"
    assert saved.read_bytes() == PNG
    assert "→ extracted/prob.zip/encfile.recovered.png" in out
    assert "열어 볼 파일: " in out and "encfile.recovered.png" in out
    assert "다음: forensic lsb extracted/prob.zip/encfile.recovered.png" in out
