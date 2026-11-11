"""별도 프로세스 실행 테스트 (Tkinter 불필요)."""

import sys
import time

import pytest

from ctfkit.cli import main
from ctfkit.gui.runner import Job, classify


def _collect(job, seconds=20, until=None):
    lines = []
    deadline = time.time() + seconds
    while time.time() < deadline:
        lines += job.poll()
        if job.done or (until and until in lines):
            return lines
        time.sleep(0.01)
    job.stop()
    raise AssertionError(f"시간 초과: {lines}")


def test_stdin_input_reaches_command():
    job = Job(["codec", "encode", "hex"], stdin="flag")
    assert "666c6167" in _collect(job)
    assert classify(job.exit_code, job.saw_error_line) == "ok"


def test_korean_output_is_not_broken():
    job = Job(["codec", "decode", "base64"], stdin="7ZWc6riA")
    assert "한글" in _collect(job)


def test_error_is_classified_as_error():
    job = Job(["codec", "decode", "nope"], stdin="abc")
    assert any(line.startswith("오류:") for line in _collect(job))
    assert classify(job.exit_code, job.saw_error_line) == "error"


def test_not_found_is_not_an_error(tmp_path):
    words = tmp_path / "words.txt"
    words.write_text("a\nb\n")
    job = Job(["hash", "crack", "5f4dcc3b5aa765d61d8327deb882cf99", f"--words={words}"])
    _collect(job)
    assert classify(job.exit_code, job.saw_error_line) == "no_result"


def test_stdout_and_stderr_keep_their_order():
    code = "import sys; print('first', file=sys.stderr); print('second'); print('third', file=sys.stderr)"
    job = Job([], command=[sys.executable, "-u", "-c", code])
    assert _collect(job) == ["first", "second", "third"]


def test_output_streams_while_running_and_stop_works():
    code = "import time; print('started', flush=True); time.sleep(60)"
    job = Job([], command=[sys.executable, "-c", code])
    _collect(job, until="started")
    assert not job.done
    job.stop()
    _collect(job)
    assert classify(job.exit_code, job.saw_error_line, job.stopped) == "stopped"


@pytest.mark.parametrize("code,saw_error,expected", [
    (0, False, "ok"),
    (1, False, "no_result"),
    (1, True, "error"),
    (2, False, "error"),
])
def test_classify(code, saw_error, expected):
    assert classify(code, saw_error) == expected


def test_ui_command_reports_missing_tkinter(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "tkinter", None)
    monkeypatch.delitem(sys.modules, "ctfkit.gui.app", raising=False)
    assert main(["ui"]) == 2
    assert "Tkinter" in capsys.readouterr().err
