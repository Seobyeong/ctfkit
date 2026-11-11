"""ctfkit forensic: 파일 형식 판별 / 문자열·플래그 추출 / 숨은 파일 탐지.

표준 라이브러리만 사용한다(EXIF·ZIP·pcap 파싱 포함). LSB 추출만 Pillow 가 있으면 켜진다.
CTF 포렌식에서 자주 하는 "이 파일 뭐지 → 문자열/메타데이터 → 뒤에 뭐 붙었나 → 안에 뭐 들었나"
(id/strings/meta/exif/carve/zip/pcap/lsb) 를 담당한다.
"""

import re
import struct
import zipfile

from ctfkit import exif as exif_mod
from ctfkit.flags import EMBEDDED_FLAG_PATTERN, compile_flag_pattern
from ctfkit.console import DEFAULT_LIMIT, emit_lines, is_quiet, log, note
from ctfkit.registry import TransformError

# 매직 바이트 테이블: (시그니처, 이름). 긴 시그니처부터 검사하도록 길이순 정렬해 쓴다.
_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG 이미지"),
    (b"\xff\xd8\xff", "JPEG 이미지"),
    (b"GIF87a", "GIF 이미지"),
    (b"GIF89a", "GIF 이미지"),
    (b"BM", "BMP 이미지"),
    (b"PK\x03\x04", "ZIP (또는 docx/jar/apk 등)"),
    (b"PK\x05\x06", "ZIP (빈 아카이브)"),
    (b"Rar!\x1a\x07", "RAR 아카이브"),
    (b"\x1f\x8b", "GZIP"),
    (b"BZh", "BZIP2"),
    (b"\xfd7zXZ\x00", "XZ"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"%PDF", "PDF 문서"),
    (b"\x7fELF", "ELF 실행 파일"),
    (b"MZ", "DOS/PE 실행 파일"),
    (b"OggS", "OGG 오디오"),
    (b"ID3", "MP3 오디오 (ID3)"),
    (b"RIFF", "RIFF (WAV/AVI)"),
    (b"\x25\x21PS", "PostScript"),
    (b"SQLite format 3\x00", "SQLite DB"),
]

# carve 에서 "본체 안에 또 다른 파일이 숨어 있나" 찾을 때 쓰는 내장 가능 형식들.
# 파일 맨 앞(오프셋 0)에 나오는 건 그 파일 자신이므로 제외하고, 그 뒤에 나오는 것만 숨은 파일로 본다.
_EMBEDDED_MARKERS = [
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"PK\x03\x04", "ZIP"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"\x1f\x8b\x08", "GZIP"),
    (b"%PDF", "PDF"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
]

GUI_HINTS = {
    "forensic": {
        "label": "포렌식",
        "order": 50,
        "group": "파일·바이너리",
        "desc": "파일 형식, 문자열, 숨은 파일, 이미지 LSB를 분석합니다.",
        "actions": {
            "meta": "요약", "id": "형식 판별", "strings": "문자열", "carve": "숨은 파일",
            "exif": "EXIF", "zip": "ZIP 목록", "pcap": "pcap 문자열", "lsb": "LSB",
        },
        "fields": {
            "file": {"label": "파일", "kind": "file"},
            "flag": {"label": "플래그 정규식"},
            "dump": {"label": "저장 경로"},
            "min_len": {"label": "최소 길이"},
            "offset": {"label": "오프셋 표시"},
            "bits": {"label": "하위 비트 수"},
            "channels": {"label": "LSB 채널 (예: rgb, r)", "default": "rgb"},
        },
    },
}


def identify(data: bytes) -> str | None:
    """매직 바이트로 파일 형식을 판별한다. 모르면 None."""
    for sig, name in sorted(_SIGNATURES, key=lambda s: -len(s[0])):
        if data.startswith(sig):
            return name
    return None


def extract_strings(data: bytes, min_len: int = 4) -> list[tuple[int, str]]:
    """출력 가능한 ASCII 가 min_len 자 이상 이어지는 구간을 (오프셋, 문자열)로 모은다."""
    # 정규식 엔진(C 구현)이 구간을 찾게 한다. 바이트를 파이썬 반복문으로 하나씩 보면 2MB 에 0.2초가 걸린다.
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % max(1, min_len))
    return [(m.start(), m.group().decode("ascii")) for m in pattern.finditer(data)]


def find_embedded(data: bytes) -> list[tuple[int, str]]:
    """오프셋 0 이후에 나타나는 파일 시그니처(= 뒤에 숨겨 붙인 파일)를 찾는다."""
    found = []
    for marker, name in _EMBEDDED_MARKERS:
        start = 1   # 0 은 파일 자신의 헤더이므로 1부터 검색
        while True:
            pos = data.find(marker, start)
            if pos == -1:
                break
            found.append((pos, name))
            start = pos + 1
    found.sort()
    return found


def _read_file(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise TransformError(f"파일을 읽을 수 없습니다: {e}") from e


def register(subparsers):
    parser = subparsers.add_parser("forensic", help="파일 형식·문자열·숨은 파일 분석")
    actions = parser.add_subparsers(dest="action", required=True, metavar="<action>")

    p_id = actions.add_parser("id", help="매직 바이트로 파일 형식 판별")
    p_id.add_argument("file", help="분석할 파일")
    p_id.set_defaults(func=_id)

    p_str = actions.add_parser("strings", help="출력 가능한 문자열 추출")
    p_str.add_argument("file", help="분석할 파일")
    p_str.add_argument("-n", "--min-len", type=int, default=4, help="최소 길이 (기본 4)")
    p_str.add_argument("--offset", action="store_true", help="오프셋(16진수)도 함께 출력")
    p_str.add_argument("-l", "--limit", type=int, default=DEFAULT_LIMIT,
                       help=f"출력할 최대 줄 수 (기본 {DEFAULT_LIMIT}, 0=전체)")
    p_str.add_argument("-g", "--grep", metavar="REGEX", help="정규식에 맞는 줄만 출력")
    p_str.set_defaults(func=_strings)

    p_carve = actions.add_parser("carve", help="뒤에 숨겨 붙인 파일(트레일러) 탐지")
    p_carve.add_argument("file", help="분석할 파일")
    p_carve.add_argument("--dump", metavar="PATH", help="첫 숨은 파일을 이 경로로 저장")
    p_carve.set_defaults(func=_carve)

    p_meta = actions.add_parser("meta", help="형식·크기·플래그 한눈에 보기")
    p_meta.add_argument("file", help="분석할 파일")
    p_meta.add_argument("--flag", metavar="REGEX", help="플래그 정규식 (기본: DH{...} 등)")
    p_meta.set_defaults(func=_meta)

    p_exif = actions.add_parser("exif", help="EXIF/TIFF 메타데이터 덤프 (JPEG/TIFF)")
    p_exif.add_argument("file", help="분석할 이미지")
    p_exif.set_defaults(func=_exif)

    p_zip = actions.add_parser("zip", help="ZIP 안의 파일 목록 (뒤에 붙은 ZIP 도 읽음)")
    p_zip.add_argument("file", help="분석할 파일")
    p_zip.set_defaults(func=_zip)

    p_pcap = actions.add_parser("pcap", help="pcap 패킷 페이로드에서 문자열 추출")
    p_pcap.add_argument("file", help="분석할 pcap 파일")
    p_pcap.add_argument("-n", "--min-len", type=int, default=4, help="최소 문자열 길이 (기본 4)")
    p_pcap.add_argument("-l", "--limit", type=int, default=DEFAULT_LIMIT,
                       help=f"출력할 최대 줄 수 (기본 {DEFAULT_LIMIT}, 0=전체)")
    p_pcap.add_argument("-g", "--grep", metavar="REGEX", help="정규식에 맞는 줄만 출력")
    p_pcap.set_defaults(func=_pcap)

    p_lsb = actions.add_parser("lsb", help="이미지 LSB 추출 (Pillow 필요)")
    p_lsb.add_argument("file", help="분석할 이미지")
    p_lsb.add_argument("-b", "--bits", type=int, default=1, help="채널별로 뽑을 하위 비트 수 (기본 1)")
    p_lsb.add_argument("-c", "--channels", default="rgb",
                       help="사용할 채널과 순서 (예: rgb, r, gb). 기본 rgb")
    p_lsb.set_defaults(func=_lsb)


def _id(args):
    data = _read_file(args.file)
    name = identify(data)
    if name is None:
        head = data[:8].hex()
        print(f"알 수 없는 형식 (앞 8바이트: {head})")
        return 1
    print(name)
    return 0


def _strings(args):
    data = _read_file(args.file)
    strings = extract_strings(data, args.min_len)
    lines = [f"{off:#010x}  {s}" if args.offset else s for off, s in strings]
    shown = emit_lines(lines, limit=args.limit, grep=args.grep)
    return 0 if shown else 1


def _carve(args):
    data = _read_file(args.file)
    embedded = find_embedded(data)
    if not embedded:
        print("숨은 파일을 찾지 못했습니다.")
        return 1
    note(f"[+] 숨은 파일 시그니처 {len(embedded)}개:")
    for off, name in embedded:
        print(f"{off:#x} {name}" if is_quiet() else f"  오프셋 {off:#x} ({off})  {name}")
    if args.dump:
        first = embedded[0][0]
        with open(args.dump, "wb") as f:
            f.write(data[first:])
        note(f"[+] 오프셋 {first:#x} 부터 끝까지 {args.dump} 에 저장 ({len(data) - first} 바이트)")
    return 0


def _meta(args):
    data = _read_file(args.file)
    print(f"파일:   {args.file}")
    print(f"크기:   {len(data)} 바이트")
    print(f"형식:   {identify(data) or '알 수 없음'}")
    embedded = find_embedded(data)
    if embedded:
        print(f"숨은 파일: {len(embedded)}개 (forensic carve 로 확인)")
    pattern = compile_flag_pattern(args.flag or EMBEDDED_FLAG_PATTERN)
    flags = sorted({m.group(0) for m in pattern.finditer(data)})
    if flags:
        print(f"플래그 후보 ({len(flags)}):")
        for fl in flags:
            print(f"  {fl.decode('ascii', 'replace')}")
    return 0


def _exif(args):
    data = _read_file(args.file)
    tags = exif_mod.parse_exif(data)
    if not tags:
        log("EXIF 는 있으나 알아본 태그가 없습니다.")
        return 1
    note(f"[+] EXIF 태그 {len(tags)}개:")
    width = max(len(name) for name, _ in tags)
    for name, value in tags:
        print(f"  {name:<{width}}  {value}")
    return 0


def _zip(args):
    try:
        zf = zipfile.ZipFile(args.file)
    except zipfile.BadZipFile as e:
        raise TransformError(f"올바른 ZIP 이 아닙니다: {e}") from e
    except OSError as e:
        raise TransformError(f"파일을 읽을 수 없습니다: {e}") from e

    with zf:
        infos = zf.infolist()
        if not infos:
            print("ZIP 이 비어 있습니다.")
            return 1
        note(f"[+] ZIP 항목 {len(infos)}개:")
        note(f"  {'이름':<32} {'크기':>10} {'압축':>10}  암호")
        for info in infos:
            enc = "O" if (info.flag_bits & 0x1) else "-"
            print(f"  {info.filename:<32} {info.file_size:>10} {info.compress_size:>10}   {enc}")
        if any(i.flag_bits & 0x1 for i in infos):
            log("  (암호가 걸린 항목이 있습니다 — hash/crack 또는 전용 도구로 공격)")
    return 0


def _read_pcap_payloads(data: bytes) -> list[bytes]:
    """classic pcap 의 패킷 페이로드 목록을 돌려준다 (pcapng 는 지원하지 않음)."""
    if len(data) < 24:
        raise TransformError("pcap 으로 보기에 너무 짧습니다")
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        en = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        en = "<"
    else:
        raise TransformError("classic pcap 매직을 찾지 못했습니다 (pcapng 는 아직 지원하지 않음)")

    payloads = []
    pos = 24  # 전역 헤더 다음부터 레코드 시작
    while pos + 16 <= len(data):
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack_from(en + "IIII", data, pos)
        pos += 16
        payloads.append(data[pos:pos + incl_len])
        pos += incl_len
    return payloads


def _pcap(args):
    data = _read_file(args.file)
    payloads = _read_pcap_payloads(data)
    blob = b"".join(payloads)
    seen = set()
    strings = []
    for _off, s in extract_strings(blob, args.min_len):
        if s not in seen:
            seen.add(s)
            strings.append(s)
    log(f"[+] 패킷 {len(payloads)}개, 페이로드 {len(blob)} 바이트")
    if not strings:
        log("페이로드에서 읽을 만한 문자열을 찾지 못했습니다.")
        return 1
    shown = emit_lines(strings, limit=args.limit, grep=args.grep)
    return 0 if shown else 1


_CHANNEL_INDEX = {"r": 0, "g": 1, "b": 2}


def _lsb(args):
    try:
        from PIL import Image
    except ImportError:
        raise TransformError(
            "LSB 추출에는 Pillow 가 필요합니다. `pip install pillow` 후 다시 시도하세요"
        ) from None

    if not 1 <= args.bits <= 8:
        raise TransformError("--bits 는 1~8 이어야 합니다")
    channels = args.channels.lower()
    if not channels or any(c not in _CHANNEL_INDEX for c in channels):
        raise TransformError("--channels 는 r/g/b 조합이어야 합니다 (예: rgb, r, gb)")
    picks = [_CHANNEL_INDEX[c] for c in channels]

    try:
        img = Image.open(args.file).convert("RGB")
    except OSError as e:
        raise TransformError(f"이미지를 열 수 없습니다: {e}") from e

    bits = []
    for pixel in img.getdata():
        for idx in picks:
            channel = pixel[idx]
            for i in range(args.bits):
                bits.append((channel >> i) & 1)

    # 비트를 8개씩 묶어 바이트로 만든 뒤 출력 가능한 문자열만 보여준다
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out.append(byte)

    text = extract_strings(bytes(out), min_len=4)
    if not text:
        log("LSB 에서 읽을 만한 문자열을 찾지 못했습니다.")
        return 1
    note("[+] LSB 에서 추출한 문자열:")
    for _, s in text[:50]:
        print(f"  {s}")
    return 0
