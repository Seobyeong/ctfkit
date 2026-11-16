"""설치된 외부 도구(file, strings, exiftool, binwalk, zsteg, checksec, tshark)를 찾아 안전하게 실행한다.

binwalk·zsteg·exiftool 같은 도구는 이미 최고 수준이라 순수 파이썬으로 다시 만들면 항상 뒤처진다.
그래서 ctfkit 은 **도구가 있으면 함께 쓰고, 없으면 내장 구현으로 대신한다.** 이 모듈은 그 공통 부분이다.

- find(name): 도구 경로. 없거나 꺼져 있으면 None.
- run(name, args): 시간 제한과 출력 크기 상한을 두고 실행한다. 도구가 멈추거나 출력이 끝없이 커져도
  ctfkit 은 멈추지 않는다. 실패는 예외가 아니라 Result 로 돌려준다 (외부 도구 실패가 분석 전체를 막지 않게).
- CTFKIT_NO_EXTERNAL=1 이면 외부 도구를 하나도 쓰지 않는다 (v0.26 과 같은 결과, 테스트·벤치마크 재현용).

명령을 셸로 실행하지 않는다(인자 목록으로 넘긴다). 파일 이름에 셸 특수 문자가 있어도 명령이 바뀌지 않는다.
"""

import os
import re
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass

DEFAULT_TIMEOUT = 10.0             # 도구 하나가 쓸 수 있는 최대 시간(초)
MAX_OUTPUT = 1024 * 1024           # 읽을 출력의 상한(바이트). 넘으면 프로세스를 끝내고 앞부분만 쓴다
_CHUNK = 64 * 1024


@dataclass(frozen=True)
class Tool:
    name: str        # 실행 파일 이름
    use: str         # 어디에 쓰는가
    fallback: str    # 없을 때 무엇으로 대신하는가 (그리고 무엇을 못 하는가)


TOOLS = [
    Tool("file", "형식 판별 (내장 표에 없는 형식)", "내장 매직 바이트 표 (20여 종)"),
    Tool("strings", "UTF-16 문자열 (윈도 실행 파일·문서 속 플래그)", "내장 구현 (ASCII 만)"),
    Tool("exiftool", "메타데이터 (PNG·PDF·문서·오디오 포함)", "내장 EXIF 파서 (JPEG·TIFF 만)"),
    Tool("binwalk", "숨은 파일 탐지 (수백 종 시그니처)", "내장 시그니처 검색 (8종)"),
    Tool("zsteg", "PNG·BMP LSB 조합 탐색", "forensic lsb (Pillow 필요, 조합 하나씩 직접)"),
    Tool("checksec", "ELF 보호 기법", "내장 ELF 파서"),
    Tool("tshark", "pcap·pcapng 프로토콜 요약", "forensic pcap (classic pcap 문자열만)"),
]
TOOL_NAMES = [tool.name for tool in TOOLS]


def disabled() -> bool:
    """CTFKIT_NO_EXTERNAL 이 켜져 있으면 외부 도구를 쓰지 않는다."""
    return os.environ.get("CTFKIT_NO_EXTERNAL", "").strip().lower() not in ("", "0", "false", "no")


def find(name: str) -> str | None:
    """도구의 실행 경로. 설치돼 있지 않거나 외부 도구가 꺼져 있으면 None."""
    if disabled():
        return None
    return shutil.which(name)


@dataclass
class Result:
    tool: str
    ok: bool = False             # 실행됐고 종료 코드가 0
    output: bytes = b""          # stdout + stderr (MAX_OUTPUT 까지)
    code: int | None = None      # 종료 코드 (끝내지 못했으면 None)
    timed_out: bool = False
    truncated: bool = False      # 출력이 상한을 넘어 잘랐다
    error: str = ""              # 실행 자체가 실패한 이유

    @property
    def text(self) -> str:
        return self.output.decode("utf-8", "replace")

    @property
    def usable(self) -> bool:
        """결과를 쓸 수 있는가. 시간이 넘었거나 출력을 잘랐어도 이미 읽은 부분은 쓴다."""
        return bool(self.output) and not self.error and (self.ok or self.timed_out or self.truncated)


def _kill(proc: subprocess.Popen) -> None:
    """프로세스와 그 자식까지 끝낸다. 윈도에서 .bat 래퍼만 끝내면 실제 도구가 남아 파이프를 붙잡는다."""
    if proc.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        else:
            os.killpg(proc.pid, 9)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


# 윈도에서 .bat/.cmd 로 설치된 도구(루비 gem 인 zsteg 등)는 cmd.exe 가 인자를 다시 해석한다. 인자 목록으로 넘겨도
# 파일 이름의 & | < > ^ % ! " 가 명령으로 바뀔 수 있으므로(문제 파일 이름으로 명령 실행), 그런 인자는 넘기지 않는다
_BATCH_UNSAFE = re.compile(r'[&|<>^%!"\r\n]')


def _is_batch(path: str) -> bool:
    return sys.platform == "win32" and path.lower().endswith((".bat", ".cmd"))


def run(name: str, args: list[str], timeout: float | None = None, max_output: int | None = None) -> Result:
    """도구를 실행해 출력을 돌려준다. 어떤 경우에도 예외를 내지 않고 timeout 남짓 안에 돌아온다.

    timeout·max_output 을 주지 않으면 모듈 상수(DEFAULT_TIMEOUT, MAX_OUTPUT)를 부를 때마다 읽는다.
    """
    timeout = DEFAULT_TIMEOUT if timeout is None else timeout
    max_output = MAX_OUTPUT if max_output is None else max_output
    result = Result(name)
    path = find(name)
    if path is None:
        result.error = "설치되지 않음"
        return result
    if _is_batch(path) and any(_BATCH_UNSAFE.search(arg) for arg in args):
        result.error = "배치 파일 도구에 cmd.exe 특수 문자가 든 인자를 넘기지 않음"
        return result

    kwargs = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    else:
        kwargs["start_new_session"] = True   # 자식까지 한 번에 끝낼 수 있게 프로세스 그룹을 따로 둔다
    try:
        proc = subprocess.Popen([path, *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, **kwargs)
    except (OSError, ValueError) as e:
        result.error = f"실행 실패: {e}"
        return result

    chunks, size = [], 0

    def reader():
        nonlocal size
        try:
            while size < max_output:
                chunk = proc.stdout.read1(_CHUNK) if hasattr(proc.stdout, "read1") else proc.stdout.read(_CHUNK)
                if not chunk:
                    return
                chunks.append(chunk)
                size += len(chunk)
        except (OSError, ValueError):
            return

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        result.timed_out = True
    elif size >= max_output:
        result.truncated = True
    if result.timed_out or result.truncated:
        _kill(proc)
        thread.join(1)   # 남은 조각을 받는다. 그래도 안 끝나면 버린다 (데몬 스레드라 종료를 막지 않는다)
    try:
        result.code = proc.wait(timeout=2 if not (result.timed_out or result.truncated) else 1)
    except subprocess.TimeoutExpired:
        _kill(proc)
    result.output = b"".join(chunks)[:max_output]
    result.ok = result.code == 0 and not result.timed_out
    return result


def missing(names: list[str]) -> list[str]:
    """names 중 설치되지 않은 도구 (외부 도구가 꺼져 있으면 빈 목록: 일부러 끈 것이므로 안내하지 않는다)."""
    if disabled():
        return []
    return [name for name in names if shutil.which(name) is None]


def install_hint(names: list[str]) -> str:
    """설치하면 더 볼 수 있는 도구를 한 줄로."""
    by_name = {tool.name: tool for tool in TOOLS}
    parts = [f"{name}({by_name[name].use.split(' (')[0]})" for name in names if name in by_name]
    return "설치하면 더 볼 수 있음: " + ", ".join(parts) + "  (ctfkit doctor)"
