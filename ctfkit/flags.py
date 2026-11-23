"""플래그 형식 정의와 탐지. auto 엔진의 종료 조건이자 XOR 알려진 평문 공격의 단서."""

import re

# 흔한 플래그 접두사. 드림핵은 DH{...}
FLAG_PREFIXES = ("DH", "flag", "FLAG", "ctf", "CTF", "picoCTF", "HTB")

# 파일 바이트 전체에서 찾을 때 쓴다. 비압축 ZIP 처럼 플래그 바로 앞에 파일 이름 등이 붙어 있을 수 있어
# 단어 경계를 요구하지 않는다 ("flag.txtDH{...}"). 오탐이 조금 늘어도 놓치는 쪽이 더 손해다.
EMBEDDED_FLAG_PATTERN = r"(?:DH|flag|ctf|picoCTF|HTB)\{[\x20-\x7e]{1,200}?\}"

# \b: "myctf{...}" 안의 "ctf{...}" 처럼 다른 단어 중간에서 잘린 플래그를 잡지 않도록
DEFAULT_FLAG_PATTERN = r"\b" + EMBEDDED_FLAG_PATTERN


def configured_pattern() -> str | None:
    """대회 설정(.ctfkit.json)의 플래그 정규식. 설정이 없으면 None."""
    from ctfkit import settings   # 순환 import 를 피한다

    return settings.current().flag


def default_pattern() -> str:
    """--flag 를 주지 않았을 때의 플래그 정규식: 대회 설정 → 기본값."""
    return configured_pattern() or DEFAULT_FLAG_PATTERN


def embedded_pattern() -> str:
    """파일 바이트에서 찾을 때의 기본 정규식: 대회 설정 → 단어 경계 없는 기본값."""
    return configured_pattern() or EMBEDDED_FLAG_PATTERN


_LITERAL_PREFIX = re.compile(r"(?:\\b)?([A-Za-z0-9_]+)\\\{")


def flag_prefixes() -> tuple[str, ...]:
    """XOR 알려진 평문 공격·레일 펜스 순위에 쓰는 접두사.

    대회 설정의 정규식이 글자 그대로의 접두사로 시작하면(예: 'picoCTF\\{.*?\\}', 'abc\\{.*?\\}') 그 접두사를 맨 앞에 더한다.
    """
    match = _LITERAL_PREFIX.match(configured_pattern() or "")
    if match and match.group(1) not in FLAG_PREFIXES:
        return (match.group(1), *FLAG_PREFIXES)
    return FLAG_PREFIXES


def compile_flag_pattern(pattern: str | None = None) -> re.Pattern:
    """플래그 정규식을 컴파일한다. pattern 이 없으면 대회 설정, 그것도 없으면 기본 형식 (대소문자 무시)."""
    pattern = pattern or default_pattern()
    try:
        return re.compile(pattern.encode(), re.IGNORECASE)
    except re.error as e:
        raise ValueError(f"잘못된 플래그 정규식: {pattern} ({e})") from e


def flag_quality(flag: bytes | None) -> float:
    """플래그가 진짜일 가능성 (0~1): 괄호 안의 글자 중 영숫자·밑줄·하이픈·공백의 비율.

    변환을 많이 시도하면 "flag{%W{*!n}" 처럼 우연히 플래그 모양이 된 쓰레기가 나온다. 실제 플래그는
    대부분 영숫자와 밑줄로 이뤄져 있으므로, 여러 후보가 같은 단계에서 나오면 이 값이 높은 쪽을 고른다.
    """
    if not flag:
        return 0.0
    body = flag[flag.find(b"{") + 1:flag.rfind(b"}")] if b"{" in flag else flag
    if not body:
        return 0.0
    return sum(chr(b).isalnum() or b in b"_- " for b in body if b < 0x80) / len(body)


# 문제 설명·안내에 흔한 "형식 예시" 의 괄호 안. 이런 것은 플래그로 보고하지 않는다 (에이전트 벤치마크의 미끼 문제에서 발견)
_PLACEHOLDER_CHARS = set(b".*?xX_- \t") | {0xE2, 0x80, 0xA6}   # 0xE2 0x80 0xA6 = "…"
_PLACEHOLDER_WORDS = {b"flag", b"flag_here", b"your_flag_here", b"flag_goes_here", b"redacted", b"example",
                      b"fake_flag", b"sample", b"placeholder", b"test", b"todo"}


def is_placeholder(flag: bytes | str) -> bool:
    """flag{...}, flag{xxxx}, DH{FLAG_HERE} 처럼 형식을 알려 주는 자리 표시인가."""
    if isinstance(flag, str):
        flag = flag.encode("utf-8", "replace")
    if b"{" not in flag:
        return False
    body = flag[flag.find(b"{") + 1:flag.rfind(b"}")]
    return not body or all(b in _PLACEHOLDER_CHARS for b in body) or body.lower() in _PLACEHOLDER_WORDS


def find_flag(data: bytes, pattern: re.Pattern) -> bytes | None:
    match = pattern.search(data)
    return match.group(0) if match else None
