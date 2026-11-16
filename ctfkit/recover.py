"""모양을 바꿔 숨긴 파일을 되살린다: 글자(hex·base64)로 적은 파일, 바이트마다 같은 키로 XOR·덧셈한 파일, 뒤집은 파일.

auto 는 "글자 플래그" 를 찾는다. 하지만 포렌식·misc 문제는 플래그가 **이미지 안에** 그려져 있는 경우가 많고, 그 이미지를
hex 로 적거나 바이트마다 128 을 더해 두는 식으로 숨긴다. 이런 파일은 글자 플래그가 없으므로 auto 로는 찾을 수 없다.

판단 기준은 파일 형식의 머리(매직 바이트)다. 바꾼 결과의 맨 앞이 PNG·ZIP·PDF 같은 알려진 머리와 맞으면 되살린 것으로 본다.
키를 모두 시도하지 않고, 머리의 첫 바이트에서 키를 계산한 뒤 나머지 바이트로 확인하므로 파일 크기와 관계없이 빠르다.
"""

import base64
import binascii
import re
from dataclasses import dataclass

from ctfkit.commands.forensic import _SIGNATURES, identify

MAX_SIZE = 50 * 1024 * 1024   # 이보다 큰 입력은 시도하지 않는다

# 확장자: 되살린 파일을 저장할 때 붙인다
_EXT = {
    "PNG": ".png", "JPEG": ".jpg", "GIF": ".gif", "BMP": ".bmp", "ZIP": ".zip", "RAR": ".rar", "GZIP": ".gz",
    "BZIP2": ".bz2", "XZ": ".xz", "7-Zip": ".7z", "PDF": ".pdf", "ELF": ".elf", "DOS/PE": ".exe", "OGG": ".ogg",
    "MP3": ".mp3", "RIFF": ".riff", "PostScript": ".ps", "SQLite": ".sqlite",
}

_HEX = re.compile(rb"(?:[0-9a-fA-F]{2})+")
_B64 = re.compile(rb"[A-Za-z0-9+/]+={0,2}")
_WS = re.compile(rb"\s+")


@dataclass
class Recovered:
    data: bytes
    steps: list      # 거꾸로 한 단계들 ("hex", "xor 0x80" ...)
    fmt: str         # 되살린 파일 형식 (forensic.identify 의 이름)

    @property
    def ext(self) -> str:
        return ext_for(self.fmt)

    def describe(self) -> str:
        return f"{' → '.join(self.steps)} → {self.fmt} ({len(self.data)} 바이트)"


def ext_for(fmt: str) -> str:
    for key, ext in _EXT.items():
        if fmt.startswith(key):
            return ext
    return ".bin"


def _decodings(data: bytes) -> list[tuple[str, bytes]]:
    """(단계 이름, 바이트) 후보. 원본을 먼저 두고, 글자 파일이면 hex·base64 로 읽은 것을 더한다."""
    out = [("", data)]
    compact = _WS.sub(b"", data)
    if len(compact) < 16:
        return out
    body = compact[2:] if compact[:2].lower() == b"0x" else compact
    if _HEX.fullmatch(body):
        out.append(("hex", bytes.fromhex(body.decode())))
    elif _B64.fullmatch(compact) and len(compact) % 4 == 0:
        try:
            out.append(("base64", base64.b64decode(compact, validate=True)))
        except (binascii.Error, ValueError):
            pass
    return out


def _table(fn) -> bytes:
    return bytes(fn(i) & 0xFF for i in range(256))


def _byte_ops(data: bytes, decoded: bool):
    """data 에 대해 머리가 맞는 (단계 이름, 변환표 또는 None) 을 하나 찾는다. None 이면 뒤집기."""
    # 원본 바이너리에는 4바이트 이상의 머리만 쓴다. 3바이트(JPEG 등)는 우연히 맞을 확률이 높다
    min_len = 3 if decoded else 4
    for sig, _ in sorted(_SIGNATURES, key=lambda s: -len(s[0])):
        if len(sig) < min_len or len(data) < len(sig):
            continue
        k = data[0] ^ sig[0]
        if k and all(data[i] ^ k == sig[i] for i in range(len(sig))):
            name = f"xor {k:#04x}" + (" (= 바이트 ±128)" if k == 0x80 else "")
            return name, _table(lambda b, k=k: b ^ k)
        d = (data[0] - sig[0]) % 256
        if d and all((data[i] - d) % 256 == sig[i] for i in range(len(sig))):
            return f"바이트마다 -{d} (mod 256)", _table(lambda b, d=d: b - d)
        if data[::-1][:len(sig)] == sig:
            return "뒤집기", None
    return None


def recover(data: bytes) -> Recovered | None:
    """data 를 되살릴 수 있으면 Recovered, 아니면 None. 원래부터 알려진 형식인 파일은 None."""
    if not data or len(data) > MAX_SIZE or identify(data):
        return None
    for label, candidate in _decodings(data):
        if len(candidate) < 8:
            continue
        steps = [label] if label else []
        fmt = identify(candidate)
        if fmt and steps:
            return Recovered(candidate, steps, fmt)
        found = _byte_ops(candidate, decoded=bool(label))
        if not found:
            continue
        name, table = found
        result = candidate[::-1] if table is None else candidate.translate(table)
        fmt = identify(result)
        if fmt:
            return Recovered(result, steps + [name], fmt)
    return None
