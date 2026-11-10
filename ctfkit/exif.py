"""EXIF/TIFF 메타데이터 파서. 표준 라이브러리(struct)만 사용한다. 외부 의존성 없음.

`forensic exif` 가 쓴다. JPEG 의 APP1("Exif\\0\\0") 안이나 TIFF 파일 맨 앞에 들어 있는
TIFF 구조(바이트 순서 → IFD0 → ExifIFD/GPSIFD)를 따라가며 태그를 읽는다.
CTF 에서 메타데이터에 플래그·힌트를 숨기는 유형(Author/Comment/GPS 등)을 겨냥한다.
"""

import struct

from ctfkit.registry import TransformError

# TIFF 타입 번호 -> 요소 하나의 바이트 수
_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8, 11: 4, 12: 8}

# 자주 쓰는 태그 이름 (IFD0 + Exif 서브 IFD 공용)
_TAGS = {
    0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model",
    0x0112: "Orientation", 0x0131: "Software", 0x0132: "DateTime",
    0x013B: "Artist", 0x8298: "Copyright",
    0x8769: "ExifOffset", 0x8825: "GPSInfo",
    0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
    0x9286: "UserComment", 0x927C: "MakerNote", 0xA420: "ImageUniqueID",
    0xA433: "LensMake", 0xA434: "LensModel",
}
_GPS_TAGS = {
    0x0000: "GPSVersionID", 0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef", 0x0004: "GPSLongitude", 0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude", 0x0012: "GPSMapDatum",
}

_EXIF_OFFSET_TAG = 0x8769
_GPS_IFD_TAG = 0x8825


def _find_tiff(data: bytes) -> bytes | None:
    """TIFF 블록(바이트 순서 표시로 시작하는 부분)을 찾는다. 못 찾으면 None."""
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return data
    if data[:2] == b"\xff\xd8":  # JPEG: 세그먼트를 훑어 APP1(Exif) 를 찾는다
        i = 2
        while i + 4 <= len(data):
            if data[i] != 0xFF:
                break
            marker = data[i + 1]
            if marker in (0xD8, 0xD9):   # SOI/EOI 는 길이가 없음
                i += 2
                continue
            if marker == 0xDA:           # SOS 이후는 압축 데이터 → 중단
                break
            (seglen,) = struct.unpack_from(">H", data, i + 2)
            seg = data[i + 4:i + 2 + seglen]
            if marker == 0xE1 and seg[:6] == b"Exif\x00\x00":
                return seg[6:]
            i = i + 2 + seglen
    return None


def _decode_value(tiff, en, typ, count, field: bytes):
    """태그 하나의 값을 디코드한다. field 는 엔트리의 값/오프셋 4바이트."""
    size = _TYPE_SIZE.get(typ, 1) * count
    if size <= 4:
        raw = field[:size]
    else:
        (off,) = struct.unpack(en + "I", field)
        raw = tiff[off:off + size]
    if len(raw) < size:
        return "(잘림)"

    if typ == 2:  # ASCII
        return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
    if typ in (1, 7):  # BYTE / UNDEFINED
        text = raw.split(b"\x00", 1)[0]
        if all(0x20 <= b <= 0x7E for b in text) and text:
            return text.decode("ascii")
        return "0x" + raw.hex()
    if typ == 3:  # SHORT
        vals = struct.unpack(en + "H" * count, raw)
        return ", ".join(str(v) for v in vals)
    if typ in (4, 9):  # LONG / SLONG
        code = "i" if typ == 9 else "I"
        return ", ".join(str(v) for v in struct.unpack(en + code * count, raw))
    if typ in (5, 10):  # RATIONAL / SRATIONAL
        code = "ii" if typ == 10 else "II"
        nums = struct.unpack(en + code * count, raw)
        parts = []
        for k in range(0, len(nums), 2):
            n, d = nums[k], nums[k + 1]
            parts.append(f"{n}/{d}" + (f" ({n / d:.4g})" if d else ""))
        return ", ".join(parts)
    return "0x" + raw.hex()


def _read_ifd(tiff, en, offset, names, out, refs):
    """IFD 하나를 읽어 (태그이름, 값) 을 out 에 넣는다. Exif/GPS 서브 IFD 오프셋은 refs 에 기록."""
    if offset == 0 or offset + 2 > len(tiff):
        return
    (count,) = struct.unpack_from(en + "H", tiff, offset)
    for i in range(count):
        base = offset + 2 + i * 12
        if base + 12 > len(tiff):
            break
        tag, typ, cnt = struct.unpack_from(en + "HHI", tiff, base)
        field = tiff[base + 8:base + 12]
        if tag == _EXIF_OFFSET_TAG:
            refs["exif"] = struct.unpack(en + "I", field)[0]
            continue
        if tag == _GPS_IFD_TAG:
            refs["gps"] = struct.unpack(en + "I", field)[0]
            continue
        if typ not in _TYPE_SIZE:
            continue
        name = names.get(tag, f"0x{tag:04x}")
        out.append((name, _decode_value(tiff, en, typ, cnt, field)))


def parse_exif(data: bytes) -> list[tuple[str, str]]:
    """EXIF 태그 목록 [(이름, 값)] 을 돌려준다. EXIF 가 없으면 TransformError."""
    tiff = _find_tiff(data)
    if tiff is None or len(tiff) < 8:
        raise TransformError("EXIF(JPEG APP1) 또는 TIFF 구조를 찾지 못했습니다")
    if tiff[:2] == b"II":
        en = "<"
    elif tiff[:2] == b"MM":
        en = ">"
    else:
        raise TransformError("TIFF 바이트 순서 표시(II/MM)가 올바르지 않습니다")

    (ifd0,) = struct.unpack_from(en + "I", tiff, 4)
    out: list[tuple[str, str]] = []
    refs: dict = {}
    _read_ifd(tiff, en, ifd0, _TAGS, out, refs)
    if "exif" in refs:
        _read_ifd(tiff, en, refs["exif"], _TAGS, out, refs)
    if "gps" in refs:
        _read_ifd(tiff, en, refs["gps"], _GPS_TAGS, out, {})
    return out
