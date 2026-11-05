"""Tkinter 화면 테스트. 화면을 열 수 없는 환경(CI 의 Linux 등)에서는 건너뛴다."""

import time

import pytest

tk = pytest.importorskip("tkinter")

from ctfkit.gui.app import App  # noqa: E402


@pytest.fixture(scope="module")
def tk_root():
    # tk.Tk() 를 한 프로세스에서 반복해 만들면 Windows 에서 가끔 Tcl 초기화에 실패하므로 하나만 만든다
    try:
        root = tk.Tk()
    except tk.TclError as e:
        pytest.skip(f"화면을 열 수 없음: {e}")
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def app(tk_root):
    window = tk.Toplevel(tk_root)
    instance = App(window)
    yield instance
    if instance.job:
        instance.job.stop()
    window.after_cancel(instance._after_id)
    window.destroy()


def _wait(app, seconds=20):
    deadline = time.time() + seconds
    while app.job and time.time() < deadline:
        app.root.update()
        time.sleep(0.01)
    assert app.job is None, "실행이 끝나지 않음"


def _output(app):
    return app.out.get("1.0", "end-1c")


def test_every_screen_can_be_built(app):
    for command in app.schema:
        app.show_command(command.name)
        for action in command.actions:
            app.show_action(action.name)
            expected = {f.dest for f in [*command.shared, *action.fields]}
            assert set(app.widgets) == expected


def test_run_shows_result_and_highlights_flag(app):
    app.show_command("auto")
    app.set_values({"data": "ZmxhZ3toZWxsb30="})
    app.run()
    _wait(app)
    assert "flag{hello}" in _output(app)
    assert app.out.tag_ranges("flag")
    assert "완료" in app.status.cget("text")


def test_error_is_shown_in_status(app):
    app.show_command("codec")
    app.set_values({"data": "!!!"})
    app.run()
    _wait(app)
    assert "오류" in _output(app)
    assert "오류" in app.status.cget("text")


def test_invalid_input_does_not_start_job(app):
    app.show_command("auto")
    app.run()
    assert app.job is None
    assert "입력" in app.status.cget("text")


def test_values_survive_switching_screens(app):
    app.show_command("auto")
    app.set_values({"data": "keep-me"})
    app.show_command("hash")
    app.show_command("auto")
    assert app.values()["data"] == "keep-me"


def test_empty_form_action_can_run(app):
    app.show_command("codec")
    app.show_action("list")
    app.run()
    _wait(app)
    assert "base64" in _output(app)
