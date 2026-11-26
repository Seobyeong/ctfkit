"""디스크 이미지 포렌식 (ctfkit/disk.py): EWF(E01) 풀기, NTFS 파일·지운 파일·ADS·미할당 덩어리, 7비트 압축 글자.

문제 파일은 저장소에 넣지 않으므로 작은 NTFS 볼륨과 E01 을 여기서 직접 만든다 (1MB, 클러스터 4KB, MFT 레코드 1KB).
"""

import io
import os
import random
import struct
import zipfile
import zlib

import pytest

from ctfkit import disk, unpack
from ctfkit.commands import triage
from ctfkit.flags import compile_flag_pattern, embedded_pattern

CL = 4096
SIZE = 256 * CL


# ---------------------------------------------------------------- NTFS 만들기

def _fname(name: str, parent: int) -> bytes:
    c = bytearray(0x42)
    c[0:6] = parent.to_bytes(6, "little")
    c[0x40], c[0x41] = len(name), 1
    return bytes(c) + name.encode("utf-16-le")


def _resident(atype: int, content: bytes, name: str = "") -> bytes:
    nm = name.encode("utf-16-le")
    coff = (0x18 + len(nm) + 7) // 8 * 8
    total = (coff + len(content) + 7) // 8 * 8
    a = bytearray(total)
    struct.pack_into("<IIBBH", a, 0, atype, total, 0, len(name), 0x18)
    struct.pack_into("<IH", a, 0x10, len(content), coff)
    a[0x18:0x18 + len(nm)] = nm
    a[coff:coff + len(content)] = content
    return bytes(a)


def _run(count: int, lcn: int) -> bytes:
    return bytes([0x21, count]) + lcn.to_bytes(2, "little", signed=True)


def _nonresident(runs: bytes, alloc: int, real: int, name: str = "") -> bytes:
    nm = name.encode("utf-16-le")
    roff = (0x40 + len(nm) + 7) // 8 * 8
    total = (roff + len(runs) + 1 + 7) // 8 * 8
    a = bytearray(total)
    struct.pack_into("<IIBBH", a, 0, 0x80, total, 1, len(name), 0x40)
    struct.pack_into("<QQH", a, 0x10, 0, max(0, alloc // CL - 1), roff)
    struct.pack_into("<QQQ", a, 0x28, alloc, real, real)
    a[0x40:0x40 + len(nm)] = nm
    a[roff:roff + len(runs)] = runs
    return bytes(a)


def _record(flags: int, *attrs: bytes) -> bytes:
    rec = bytearray(1024)
    rec[:4] = b"FILE"
    struct.pack_into("<HH", rec, 4, 0x30, 3)
    struct.pack_into("<H", rec, 0x14, 0x38)
    struct.pack_into("<H", rec, 0x16, flags)
    off = 0x38
    for a in attrs:
        rec[off:off + len(a)] = a
        off += len(a)
    rec[off:off + 4] = b"\xff\xff\xff\xff"
    usa = bytearray(b"\x07\x00")
    for i in (1, 2):
        usa += rec[i * 512 - 2:i * 512]
        rec[i * 512 - 2:i * 512] = b"\x07\x00"
    rec[0x30:0x36] = usa
    return bytes(rec)


def _boot(total_sectors: int) -> bytes:
    b = bytearray(512)
    b[0:3] = b"\xebR\x90"
    b[3:11] = b"NTFS    "
    struct.pack_into("<HB", b, 11, 512, 8)
    struct.pack_into("<QQQ", b, 0x28, total_sectors, 4, 2)
    b[0x40] = 0xF6          # 레코드 1024 바이트
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def make_ntfs(flag_in_deleted: bytes = b"deleted content", wipe_boot: bool = False) -> bytes:
    img = bytearray(SIZE)
    used = set(range(0, 12)) | {20, 21}
    bitmap = bytearray(32)
    for c in used:
        bitmap[c >> 3] |= 1 << (c & 7)
    recs = {
        0: _record(1, _resident(0x30, _fname("$MFT", 5)), _nonresident(_run(8, 4), 8 * CL, 8 * CL)),
        5: _record(3, _resident(0x30, _fname(".", 5))),
        6: _record(1, _resident(0x30, _fname("$Bitmap", 5)), _resident(0x80, bytes(bitmap))),
        24: _record(1, _resident(0x30, _fname("hello.txt", 5)), _resident(0x80, b"hello world")),
        25: _record(1, _resident(0x30, _fname("big.bin", 5)), _nonresident(_run(2, 20), 2 * CL, 5000)),
        26: _record(1, _resident(0x30, _fname("notes.txt", 5)), _resident(0x80, b"plain"),
                    _resident(0x80, b"hidden stream", "secret")),
        27: _record(0, _resident(0x30, _fname("gone.txt", 5)), _resident(0x80, flag_in_deleted)),
        28: _record(0, _resident(0x30, _fname("seg1", 5)), _nonresident(b"", 2 * CL, 0)),
        29: _record(0, _resident(0x30, _fname("seg2", 5)), _nonresident(b"", 3 * CL, 0)),
        30: _record(3, _resident(0x30, _fname("dir", 5))),
        31: _record(1, _resident(0x30, _fname("inner.txt", 30)), _resident(0x80, b"inside dir")),
    }
    for n, rec in recs.items():
        img[4 * CL + n * 1024:4 * CL + (n + 1) * 1024] = rec
    img[20 * CL:20 * CL + 5000] = (b"BIG" * 2000)[:5000]
    img[40 * CL:42 * CL] = (b"%PDF-1.7 part one " * 500)[:2 * CL]          # 지운 seg1 의 내용 (2클러스터)
    img[60 * CL:63 * CL] = (b"part two %%EOF " * 900)[:3 * CL]             # 지운 seg2 의 내용 (3클러스터)
    img[90 * CL:91 * CL] = b"\xaa" * CL                                     # 한 바이트로 채운 클러스터는 빈 것
    boot = _boot(SIZE // 512 - 1)
    img[0:512] = b"\xaa" * 512 if wipe_boot else boot
    img[SIZE - 512:SIZE] = boot
    return bytes(img)


def items(path):
    notes = []
    out = {i.rel: i for i in disk.ntfs_items(str(path), 1 << 20, 1 << 24, notes)}
    return out, notes


def test_ntfs_files_deleted_ads_and_unallocated(tmp_path):
    path = tmp_path / "disk.raw"
    path.write_bytes(make_ntfs())
    got, notes = items(path)
    assert got["hello.txt"].data == b"hello world"
    assert got["big.bin"].data == (b"BIG" * 2000)[:5000]          # 실제 크기에서 자른다 (할당은 2클러스터)
    assert got["dir/inner.txt"].data == b"inside dir"             # 부모 디렉터리로 경로를 만든다
    assert got["notes.txt~secret"].data == b"hidden stream"       # ADS 는 이름~스트림
    assert "ADS" in got["notes.txt~secret"].note
    assert got["_deleted/gone.txt"].data == b"deleted content"
    assert got["_unallocated/clusters_40-41.bin"].data.startswith(b"%PDF")
    assert "seg1" in got["_unallocated/clusters_40-41.bin"].note  # 할당 크기가 같은 지운 파일
    assert "_unallocated/clusters_90-90.bin" not in got           # 0xAA 로만 채운 클러스터는 빈 것
    joined = got["_unallocated/joined_seg1+seg2.bin"]
    assert joined.data[:4] == b"%PDF" and b"part two" in joined.data[2 * CL:]   # 이름 순서 seg1 → seg2
    assert len(joined.data) == 5 * CL and "추정" in joined.note
    assert not any(rel.startswith("$") for rel in got)            # 시스템 파일은 꺼내지 않는다
    assert any("지운 파일 1개" in n for n in notes)
    assert any("위치 정보가 지워진 지운 파일 2개" in n for n in notes)


def test_join_needs_unique_match():
    runs = [(40, 42), (60, 63)]
    assert disk._join_lost([("seg2", 3), ("seg1", 2)], runs) == [("seg1", 40, 42), ("seg2", 60, 63)]
    assert disk._join_lost([("a", 2), ("b", 2)], runs) is None        # 같은 덩어리 둘
    assert disk._join_lost([("a", 2), ("b", 7)], runs) is None        # 짝 없음
    assert disk._join_lost([("a", 2)], runs) is None                  # 하나뿐이면 잇지 않는다


def test_wiped_boot_sector_uses_backup(tmp_path):
    path = tmp_path / "broken.raw"
    path.write_bytes(make_ntfs(wipe_boot=True))
    assert unpack.kind(str(path)) == "ntfs"
    got, notes = items(path)
    assert got["hello.txt"].data == b"hello world"
    assert any("백업 부트 섹터" in n for n in notes)


def test_mbr_partition(tmp_path):
    mbr = bytearray(512)
    struct.pack_into("<B", mbr, 446 + 4, 0x07)
    struct.pack_into("<II", mbr, 446 + 8, 2048, SIZE // 512)
    mbr[510:512] = b"\x55\xaa"
    path = tmp_path / "part.raw"
    path.write_bytes(bytes(mbr) + bytes(2048 * 512 - 512) + make_ntfs())
    vols = disk.find_volumes(str(path))
    assert [v.offset for v in vols] == [2048 * 512]
    got, _ = items(path)
    assert got["hello.txt"].data == b"hello world"


def test_not_a_disk(tmp_path):
    path = tmp_path / "noise.bin"
    path.write_bytes(random.Random(1).randbytes(64 * 1024))
    assert disk.find_volumes(str(path)) == []
    assert unpack.kind(str(path)) is None


# ---------------------------------------------------------------- EWF 만들기

def make_ewf(raw: bytes, chunk: int = 32 * 1024) -> bytes:
    def desc(kind: bytes, pos: int, nxt: int, size: int) -> bytes:
        return kind.ljust(16, b"\x00") + struct.pack("<QQ", nxt, size) + bytes(44)

    out = bytearray(disk.EWF_MAGIC + b"\x01" + struct.pack("<HH", 1, 0))
    chunks = [raw[i:i + chunk] for i in range(0, len(raw), chunk)]
    volume = bytearray(1052)
    struct.pack_into("<IIIQ", volume, 4, len(chunks), chunk // 512, 512, len(raw) // 512)
    pos = len(out)
    out += desc(b"volume", pos, pos + 76 + len(volume), 76 + len(volume)) + volume
    sectors_pos = len(out)
    body, entries = bytearray(), []
    for i, c in enumerate(chunks):
        off = sectors_pos + 76 + len(body)
        if i == 1:                                   # 하나는 압축하지 않고 (뒤에 체크섬 4바이트)
            body += c + struct.pack("<I", zlib.adler32(c))
            entries.append(off)
        else:
            body += zlib.compress(c)
            entries.append(off | 0x80000000)
    table_pos = sectors_pos + 76 + len(body)
    out += desc(b"sectors", sectors_pos, table_pos, 76 + len(body)) + body
    table = struct.pack("<IIQII", len(entries), 0, 0, 0, 0) + struct.pack(f"<{len(entries)}I", *entries) + bytes(4)
    done_pos = table_pos + 76 + len(table)
    out += desc(b"table", table_pos, done_pos, 76 + len(table)) + table
    out += desc(b"done", done_pos, done_pos, 76)
    return bytes(out)


def test_ewf_roundtrip(tmp_path):
    raw = make_ntfs()
    path = tmp_path / "image.E01"
    path.write_bytes(make_ewf(raw))
    assert unpack.kind(str(path)) == "ewf"
    assert disk.ewf_info(str(path)).size == len(raw)
    assert b"".join(disk.ewf_read(str(path), 1 << 30)) == raw
    with pytest.raises(disk.DiskError, match="상한"):
        next(disk.ewf_read(str(path), 1024))          # 머리에 적힌 크기가 상한보다 크면 풀지 않는다


def test_unpack_ewf_then_ntfs(tmp_path):
    path = tmp_path / "image.E01"
    path.write_bytes(make_ewf(make_ntfs()))
    first = unpack.extract(str(path), str(tmp_path / "out"))
    assert [os.path.basename(f) for f in first.files] == ["image.raw"]
    second = unpack.extract(first.files[0], str(tmp_path / "out2"))
    names = {os.path.relpath(f, tmp_path / "out2").replace(os.sep, "/") for f in second.files}
    assert {"hello.txt", "notes.txt~secret", "_deleted/gone.txt"} <= names
    assert any("지운" in v for v in second.labels.values())


def test_start_finds_flag_in_deleted_file_inside_e01(tmp_path, capsys, monkeypatch):
    from ctfkit.cli import main

    monkeypatch.setenv("CTFKIT_AGENT", "0")
    zpath = tmp_path / "chall.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("Image.E01", make_ewf(make_ntfs(b"DH{found_in_deleted_record}")))
    code = main(["start", str(zpath), "--root", str(tmp_path / "work")])
    out = capsys.readouterr().out
    assert code == 0
    assert "DH{found_in_deleted_record}" in out and "_deleted/gone.txt" in out
    assert "EWF(E01) 디스크 이미지 → 원본 디스크로 풂" in out


def test_forensic_disk_command(tmp_path, capsys):
    from ctfkit.cli import main

    path = tmp_path / "image.E01"
    path.write_bytes(make_ewf(make_ntfs()))
    code = main(["forensic", "disk", str(path), "-o", str(tmp_path / "out")])
    out = capsys.readouterr().out
    assert code == 0
    assert "hello.txt" in out and "_deleted/gone.txt  (지운 파일)" in out
    assert (tmp_path / "out" / "image.raw.d" / "dir" / "inner.txt").read_bytes() == b"inside dir"


# ---------------------------------------------------------------- 7비트 압축 글자·UTF-16·LSB

def test_find_7bit_every_alignment():
    pattern = compile_flag_pattern(embedded_pattern())
    noise = random.Random(7).randbytes(4000)
    for k in range(9):
        packed = disk.pack_7bit(b"a" * k + b"DH{seven_bit_packed}")
        data = noise[:1000] + packed + noise[1000:]
        assert [f for _, f in disk.find_7bit(data, ("DH",), pattern)] == [b"DH{seven_bit_packed}"]


def test_find_7bit_no_false_positives_on_noise():
    pattern = compile_flag_pattern(embedded_pattern())
    data = random.Random(3).randbytes(4 << 20)
    assert disk.find_7bit(data, ("DH", "flag", "ctf"), pattern) == []


def test_triage_finds_7bit_and_utf16(tmp_path):
    pattern = triage.compile_pattern(None)
    path = tmp_path / "Windows.edb"
    path.write_bytes(b"\x00" * 4 + b"\xef\xcd\xab\x89" + bytes(100) + disk.pack_7bit(b"DH{in_search_index}") + bytes(50))
    report = triage.analyze(str(path), pattern, use_external=False)
    assert report.fmt.startswith("ESE")
    assert [f for f, _ in report.flags] == ["DH{in_search_index}"]
    assert "7비트" in report.evidence["DH{in_search_index}"]


def test_triage_lsb(tmp_path):
    Image = pytest.importorskip("PIL.Image")
    msg = b"DH{lsb_in_rgb}"
    bits = [int(b) for byte in msg for b in f"{byte:08b}"]
    img = Image.new("RGB", (16, 16), (200, 100, 50))
    px = img.load()
    i = 0
    for y in range(16):
        for x in range(16):
            rgb = list(px[x, y])
            for c in range(3):
                if i < len(bits):
                    rgb[c] = (rgb[c] & ~1) | bits[i]
                    i += 1
            px[x, y] = tuple(rgb)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    path = tmp_path / "bear.png"
    path.write_bytes(buf.getvalue())
    report = triage.analyze(str(path), triage.compile_pattern(None), use_external=False)
    assert report.flags == [("DH{lsb_in_rgb}", "LSB 1비트 (rgb)")]
