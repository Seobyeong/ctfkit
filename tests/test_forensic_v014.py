"""forensic v0.14 추가 기능 테스트 (exif / zip / pcap). 모두 표준 라이브러리만으로 검증."""

import struct
import zipfile

import pytest

from ctfkit import exif
from ctfkit.cli import main


def _tiff() -> bytes:
    """IFD0 에 Make/Orientation/Software 를 담은 최소 TIFF(리틀엔디언)."""
    hdr = b"II" + struct.pack("<HI", 42, 8)         # 바이트순서, 매직, IFD0 오프셋=8
    e1 = struct.pack("<HHII", 0x010F, 2, 5, 50)     # Make  ASCII(5)  -> 오프셋 50
    e2 = struct.pack("<HHII", 0x0112, 3, 1, 1)      # Orientation SHORT=1 (inline)
    e3 = struct.pack("<HHII", 0x0131, 2, 7, 55)     # Software ASCII(7) -> 오프셋 55
    ifd = struct.pack("<H", 3) + e1 + e2 + e3 + struct.pack("<I", 0)
    data = b"ACME\x00" + b"ctfkit\x00"
    blob = hdr + ifd + data
    assert len(blob) == 62
    return blob


def _jpeg_with_exif() -> bytes:
    seg = b"Exif\x00\x00" + _tiff()
    app1 = b"\xff\xe1" + struct.pack(">H", len(seg) + 2) + seg
    return b"\xff\xd8" + app1 + b"\xff\xd9"


# --- exif 파서 ---

def test_parse_exif_tiff():
    tags = dict(exif.parse_exif(_tiff()))
    assert tags["Make"] == "ACME"
    assert tags["Software"] == "ctfkit"
    assert tags["Orientation"] == "1"


def test_parse_exif_jpeg_wrapper():
    tags = dict(exif.parse_exif(_jpeg_with_exif()))
    assert tags["Make"] == "ACME"


def test_parse_exif_missing():
    with pytest.raises(exif.TransformError):
        exif.parse_exif(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)


def test_exif_command(tmp_path, capsys):
    p = tmp_path / "pic.jpg"
    p.write_bytes(_jpeg_with_exif())
    assert main(["forensic", "exif", str(p)]) == 0
    out = capsys.readouterr().out
    assert "Make" in out and "ACME" in out and "ctfkit" in out


# --- zip ---

def test_zip_lists_entries(tmp_path, capsys):
    p = tmp_path / "a.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("flag.txt", "DH{zip}")
        z.writestr("readme.md", "hello")
    assert main(["forensic", "zip", str(p)]) == 0
    out = capsys.readouterr().out
    assert "flag.txt" in out and "readme.md" in out


def test_zip_reads_trailing_appended(tmp_path, capsys):
    # PNG 헤더 뒤에 ZIP 을 붙여도 zipfile 은 끝의 중앙 디렉터리로 읽어낸다
    p = tmp_path / "stego.png"
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("secret.txt", "hi")
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16 + buf.getvalue())
    assert main(["forensic", "zip", str(p)]) == 0
    assert "secret.txt" in capsys.readouterr().out


def test_zip_bad_file(tmp_path, capsys):
    p = tmp_path / "nope.zip"
    p.write_bytes(b"not a zip")
    assert main(["forensic", "zip", str(p)]) == 2
    assert "ZIP" in capsys.readouterr().err


# --- pcap ---

def _pcap(payloads) -> bytes:
    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # 리틀엔디언 파일
    out = gh
    for p in payloads:
        out += struct.pack("<IIII", 0, 0, len(p), len(p)) + p
    return out


def test_pcap_extracts_strings(tmp_path, capsys):
    p = tmp_path / "cap.pcap"
    p.write_bytes(_pcap([b"GET /index", b"DH{pcap_flag}"]))
    assert main(["forensic", "pcap", str(p)]) == 0
    cap = capsys.readouterr()
    assert "DH{pcap_flag}" in cap.out
    assert "패킷 2개" in cap.err          # 요약은 stderr 로


def test_pcap_rejects_non_pcap(tmp_path, capsys):
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x00" * 64)
    assert main(["forensic", "pcap", str(p)]) == 2
    assert "pcap" in capsys.readouterr().err
