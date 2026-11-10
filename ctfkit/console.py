"""명령어들이 공통으로 쓰는 입출력 도우미.

출력 규칙(토큰·파이프 효율): **stdout 은 최종 답**, **stderr 는 진행·안내 로그**.
AI 나 다른 명령에 결과를 넘길 때 답만 가져가도록 둘을 분리한다. `-q/--quiet` 를 주면
stderr 안내를 끄고 답만 남긴다(`log()` 가 이 플래그를 따른다). 오류 메시지는 끄지 않는다.
"""

import re
import sys

from ctfkit.registry import TransformError

# -q/--quiet 로 켜지는 전역 플래그. cli.main 이 설정하고 log() 가 참고한다.
QUIET = False


def log(*args, **kwargs) -> None:
    """진행·안내 메시지를 stderr 로 출력한다. --quiet 면 생략한다 (답이 아님)."""
    if QUIET:
        return
    kwargs["file"] = sys.stderr
    print(*args, **kwargs)


def emit_lines(lines, *, limit: int = 0, grep: str | None = None) -> int:
    """여러 줄 결과를 stdout 으로 내보내되, 소스에서 필터·상한을 적용한다 (토큰 절약).

    - grep: 정규식에 맞는 줄만 남긴다.
    - limit: 양수면 그 개수까지만 출력하고, 잘린 개수를 stderr 로 알린다(--quiet 면 생략).
    돌려주는 값은 실제로 출력한 줄 수.
    """
    if grep:
        try:
            pat = re.compile(grep)
        except re.error as e:
            raise TransformError(f"잘못된 --grep 정규식: {grep} ({e})") from e
        lines = [ln for ln in lines if pat.search(ln)]

    shown = lines if limit <= 0 else lines[:limit]
    for ln in shown:
        print(ln)
    hidden = len(lines) - len(shown)
    if hidden > 0:
        log(f"... ({hidden}개 더 있음; --limit 0 으로 전체 출력)")
    return len(shown)


def parse_key(text: str) -> bytes:
    """키/시크릿 인자를 bytes 로. '0x' 접두사면 16진수로, 아니면 UTF-8 로 해석한다.

    hash(HMAC)·jwt 등 '키' 를 받는 명령이 공통으로 쓴다. 바이너리 키를 커맨드라인에
    넣어야 할 때가 있어서 16진수 입력(0x..)을 함께 지원한다.
    """
    if text[:2].lower() == "0x":
        try:
            return bytes.fromhex(text[2:])
        except ValueError as e:
            raise TransformError(f"잘못된 16진수 키: {text} ({e})") from e
    return text.encode("utf-8")


def read_input(data: str | None, file: str | None) -> bytes:
    """입력을 bytes 로 읽는다. 우선순위: --file > 인자 문자열 > stdin('-' 또는 생략)."""
    if file:
        with open(file, "rb") as f:
            return f.read()
    if data is not None and data != "-":
        return data.encode("utf-8")
    # 파이프 입력 끝에 붙는 줄바꿈(Windows는 \r\n)은 입력의 일부로 보지 않는다
    return sys.stdin.buffer.read().rstrip(b"\r\n")


def _is_printable(text: str) -> bool:
    return all(ch.isprintable() or ch in "\n\r\t" for ch in text)


def preview(data: bytes, width: int = 60) -> str:
    """한 줄 미리보기. 읽을 수 있으면 텍스트, 아니면 'hex:' 로 시작하는 16진수."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None

    if text is not None and _is_printable(text):
        text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
        return text if len(text) <= width else text[:width - 3] + "..."
    hex_text = "hex:" + data.hex()
    return hex_text if len(hex_text) <= width else hex_text[:width - 3] + "..."


def write_output(result: bytes) -> None:
    """결과를 출력한다. 사람이 읽을 수 없는 바이트면 hex 로 대신 보여준다."""
    try:
        text = result.decode("utf-8")
    except UnicodeDecodeError:
        text = None

    if text is not None and _is_printable(text):
        print(text)
    else:
        print("(출력할 수 없는 바이트라 hex로 표시합니다)", file=sys.stderr)
        print(result.hex())
