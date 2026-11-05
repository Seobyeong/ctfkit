"""플래그 형식 정의와 탐지. auto 엔진의 종료 조건이자 XOR 알려진 평문 공격의 단서."""

import re

# 흔한 플래그 접두사. 드림핵은 DH{...}
FLAG_PREFIXES = ("DH", "flag", "FLAG", "ctf", "CTF", "picoCTF", "HTB")

# 파일 바이트 전체에서 찾을 때 쓴다. 비압축 ZIP 처럼 플래그 바로 앞에 파일 이름 등이 붙어 있을 수 있어
# 단어 경계를 요구하지 않는다 ("flag.txtDH{...}"). 오탐이 조금 늘어도 놓치는 쪽이 더 손해다.
EMBEDDED_FLAG_PATTERN = r"(?:DH|flag|ctf|picoCTF|HTB)\{[\x20-\x7e]{1,200}?\}"

# \b: "myctf{...}" 안의 "ctf{...}" 처럼 다른 단어 중간에서 잘린 플래그를 잡지 않도록
DEFAULT_FLAG_PATTERN = r"\b" + EMBEDDED_FLAG_PATTERN


def compile_flag_pattern(pattern: str | None = None) -> re.Pattern:
    """플래그 정규식을 컴파일한다. pattern 이 없으면 기본 형식을 쓴다 (대소문자 무시)."""
    try:
        return re.compile((pattern or DEFAULT_FLAG_PATTERN).encode(), re.IGNORECASE)
    except re.error as e:
        raise ValueError(f"잘못된 플래그 정규식: {pattern} ({e})") from e


def find_flag(data: bytes, pattern: re.Pattern) -> bytes | None:
    match = pattern.search(data)
    return match.group(0) if match else None
