"""명령어들이 공통으로 쓰는 입출력 도우미."""

import sys


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
