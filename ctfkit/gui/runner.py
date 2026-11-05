"""ctfkit 명령을 별도 프로세스로 실행하고 출력을 줄 단위로 전달한다.

별도 프로세스를 쓰면 오래 걸리는 작업도 화면을 멈추지 않고, 언제든 중지할 수 있으며,
명령에서 예외가 나도 화면이 함께 죽지 않는다.
"""

import os
import queue
import subprocess
import sys
import threading

_PACKAGE_PARENT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ERROR_PREFIXES = ("오류:", "Traceback")


def _child_env() -> dict:
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"   # Windows 파이프의 기본 인코딩(cp949)으로 한글이 깨지지 않게
    # 설치하지 않고 소스에서 실행해도, 어느 폴더에서 실행해도 ctfkit 을 찾을 수 있게
    paths = [_PACKAGE_PARENT, env["PYTHONPATH"]] if env.get("PYTHONPATH") else [_PACKAGE_PARENT]
    env["PYTHONPATH"] = os.pathsep.join(paths)
    return env


class Job:
    """실행 중인 명령 하나. 출력은 이 Job 의 큐에만 쌓이므로 이전 작업과 섞이지 않는다."""

    def __init__(self, argv: list, stdin: str | None = None, command: list | None = None):
        self.stopped = False
        self.saw_error_line = False
        self._queue = queue.Queue()
        self._reading = True
        # stdout 과 stderr 를 한 파이프로 합쳐야 명령이 출력한 순서가 그대로 유지된다
        self._proc = subprocess.Popen(
            command or [sys.executable, "-u", "-m", "ctfkit", *argv],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=_child_env(),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        threading.Thread(target=self._feed, args=(stdin,), daemon=True).start()
        threading.Thread(target=self._read, daemon=True).start()

    def _feed(self, stdin: str | None) -> None:
        try:
            if stdin:
                self._proc.stdin.write(stdin.encode("utf-8"))
            self._proc.stdin.close()
        except OSError:
            pass   # 입력을 다 읽기 전에 프로세스가 끝난 경우

    def _read(self) -> None:
        for raw in self._proc.stdout:
            self._queue.put(raw.decode("utf-8", "replace").rstrip("\r\n"))
        self._proc.stdout.close()
        self._queue.put(None)

    def poll(self, limit: int = 500) -> list:
        """쌓인 출력을 최대 limit 줄 꺼낸다."""
        lines = []
        while len(lines) < limit:
            try:
                line = self._queue.get_nowait()
            except queue.Empty:
                break
            if line is None:
                self._reading = False
                break
            self.saw_error_line = self.saw_error_line or line.startswith(ERROR_PREFIXES)
            lines.append(line)
        return lines

    @property
    def done(self) -> bool:
        return not self._reading and self._proc.poll() is not None

    @property
    def exit_code(self):
        return self._proc.poll()

    def stop(self) -> None:
        if self._proc.poll() is None:
            self.stopped = True
            self._proc.terminate()


def classify(exit_code: int, saw_error_line: bool = False, stopped: bool = False) -> str:
    """결과 상태: ok / no_result / error / stopped.

    명령들은 '찾지 못함' 도 종료 코드 1 로 알리므로 코드만으로 오류를 판단하지 않는다.
    """
    if stopped:
        return "stopped"
    if exit_code == 0:
        return "ok"
    if exit_code != 1 or saw_error_line:
        return "error"
    return "no_result"
