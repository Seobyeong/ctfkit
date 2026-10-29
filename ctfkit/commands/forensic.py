"""ctfkit forensic: 파일 형식 판별 / 문자열·플래그 추출 / 숨은 파일 탐지.

표준 라이브러리만 사용한다. LSB 추출은 Pillow 가 있으면 켜지는 선택 기능.
CTF 포렌식에서 가장 자주 하는 "이 파일 뭐지 → 문자열 뽑기 → 뒤에 뭐 붙었나" 를 담당한다.
"""

import re
import sys

from ctfkit.flags import compile_flag_pattern
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


def identify(data: bytes) -> str | None:
    """매직 바이트로 파일 형식을 판별한다. 모르면 None."""
    for sig, name in sorted(_SIGNATURES, key=lambda s: -len(s[0])):
        if data.startswith(sig):
            return name
    return None


def extract_strings(data: bytes, min_len: int = 4) -> list[tuple[int, str]]:
    """출력 가능한 ASCII 가 min_len 자 이상 이어지는 구간을 (오프셋, 문자열)로 모은다."""
    results = []
    cur = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= min_len:
                results.append((start, cur.decode("ascii")))
            cur = bytearray()
    if len(cur) >= min_len:
        results.append((start, cur.decode("ascii")))
    return results


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
    p_str.set_defaults(func=_strings)

    p_carve = actions.add_parser("carve", help="뒤에 숨겨 붙인 파일(트레일러) 탐지")
    p_carve.add_argument("file", help="분석할 파일")
    p_carve.add_argument("--dump", metavar="PATH", help="첫 숨은 파일을 이 경로로 저장")
    p_carve.set_defaults(func=_carve)

    p_meta = actions.add_parser("meta", help="형식·크기·플래그 한눈에 보기")
    p_meta.add_argument("file", help="분석할 파일")
    p_meta.add_argument("--flag", metavar="REGEX", help="플래그 정규식 (기본: DH{...} 등)")
    p_meta.set_defaults(func=_meta)

    p_lsb = actions.add_parser("lsb", help="이미지 LSB 추출 (Pillow 필요)")
    p_lsb.add_argument("file", help="분석할 이미지")
    p_lsb.add_argument("-b", "--bits", type=int, default=1, help="채널별로 뽑을 하위 비트 수 (기본 1)")
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
    for off, s in strings:
        if args.offset:
            print(f"{off:#010x}  {s}")
        else:
            print(s)
    return 0 if strings else 1


def _carve(args):
    data = _read_file(args.file)
    embedded = find_embedded(data)
    if not embedded:
        print("숨은 파일을 찾지 못했습니다.")
        return 1
    print(f"[+] 숨은 파일 시그니처 {len(embedded)}개:")
    for off, name in embedded:
        print(f"  오프셋 {off:#x} ({off})  {name}")
    if args.dump:
        first = embedded[0][0]
        with open(args.dump, "wb") as f:
            f.write(data[first:])
        print(f"[+] 오프셋 {first:#x} 부터 끝까지 {args.dump} 에 저장 ({len(data) - first} 바이트)")
    return 0


def _meta(args):
    data = _read_file(args.file)
    print(f"파일:   {args.file}")
    print(f"크기:   {len(data)} 바이트")
    print(f"형식:   {identify(data) or '알 수 없음'}")
    embedded = find_embedded(data)
    if embedded:
        print(f"숨은 파일: {len(embedded)}개 (forensic carve 로 확인)")
    pattern = compile_flag_pattern(args.flag)
    flags = sorted({m.group(0) for m in pattern.finditer(data)})
    if flags:
        print(f"플래그 후보 ({len(flags)}):")
        for fl in flags:
            print(f"  {fl.decode('ascii', 'replace')}")
    return 0


def _lsb(args):
    try:
        from PIL import Image
    except ImportError:
        raise TransformError(
            "LSB 추출에는 Pillow 가 필요합니다. `pip install pillow` 후 다시 시도하세요"
        ) from None

    if not 1 <= args.bits <= 8:
        raise TransformError("--bits 는 1~8 이어야 합니다")
    try:
        img = Image.open(args.file).convert("RGB")
    except OSError as e:
        raise TransformError(f"이미지를 열 수 없습니다: {e}") from e

    bits = []
    for pixel in img.getdata():
        for channel in pixel:
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
        print("LSB 에서 읽을 만한 문자열을 찾지 못했습니다.", file=sys.stderr)
        return 1
    print("[+] LSB 에서 추출한 문자열:")
    for _, s in text[:50]:
        print(f"  {s}")
    return 0
