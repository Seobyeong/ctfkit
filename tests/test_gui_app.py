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


# --- 화면 정돈 (사이드바 묶음, 옵션 접기, 플래그 줄) ---

from ctfkit.gui.app import split_fields  # noqa: E402


def test_every_command_has_a_sidebar_group(app):
    groups = [c.group for c in app.schema]
    assert "기타" not in groups, "새 명령의 GUI_HINTS 에 group 을 지정하세요"
    # 같은 묶음은 사이드바에서 이어져 있어야 한다 (머리글이 두 번 나오지 않게)
    seen = []
    for group in groups:
        if not seen or seen[-1] != group:
            seen.append(group)
    assert len(seen) == len(set(seen))


def test_split_fields_folds_only_when_many_optional(app):
    auto = next(c for c in app.schema if c.name == "auto").actions[0].fields
    shown, folded = split_fields(auto)
    assert [f.dest for f in shown] == ["data", "file"]          # 입력과 입력 파일은 항상 보인다
    assert {f.dest for f in folded} == {"depth", "beam", "flag", "top"}

    hash_id = next(c for c in app.schema if c.name == "hash").actions[0].fields
    assert split_fields(hash_id) == (list(hash_id), [])          # 옵션이 적으면 접지 않는다


def test_folded_options_toggle_and_keep_widgets(app):
    app.show_command("auto")
    assert app.folded_widgets and not app.expanded[("auto", None)]
    assert all(not w.winfo_manager() for w in app.folded_widgets)   # 접힌 상태
    assert "depth" in app.widgets                                   # 접혀 있어도 값은 유지된다
    app._toggle_folded()
    assert all(w.winfo_manager() == "grid" for w in app.folded_widgets)
    app._toggle_folded()
    assert all(not w.winfo_manager() for w in app.folded_widgets)


def test_folded_options_open_when_value_was_changed(app):
    app.show_command("auto")
    app.set_values({"depth": "9"})
    app.show_command("hash")
    app.show_command("auto")
    # 바꿔 둔 값이 숨어 있으면 실행 결과가 왜 다른지 알 수 없으므로 펼쳐서 보여 준다
    assert app.expanded[("auto", None)]
    assert app.values()["depth"] == "9"
    app.set_values({"depth": "6"})


def test_flag_bar_shows_flag_and_copies_it(app):
    app.show_command("auto")
    app.set_values({"data": "ZmxhZ3toZWxsb30="})
    assert not app.flag_bar.winfo_manager()
    app.run()
    _wait(app)
    assert app.flags == ["flag{hello}"]
    assert app.flag_var.get() == "flag{hello}"
    assert app.flag_bar.winfo_manager() == "pack"
    app.copy_flag()
    assert app.root.clipboard_get() == "flag{hello}"


def test_copy_command_gives_runnable_command(app):
    app.show_command("hash")
    app.show_action("id")
    app.set_values({"digest": "5f4dcc3b5aa765d61d8327deb882cf99"})
    app.run()
    _wait(app)
    app.copy_command()
    assert app.root.clipboard_get() == "ctfkit hash id 5f4dcc3b5aa765d61d8327deb882cf99"


def test_clear_resets_output_flag_bar_and_command(app):
    app.show_command("auto")
    app.set_values({"data": "ZmxhZ3toZWxsb30="})
    app.run()
    _wait(app)
    app.clear()
    assert _output(app) == ""
    assert app.flags == [] and not app.flag_bar.winfo_manager()
    assert app.cmd_var.get() == ""
    assert app.hint.winfo_manager() == "place"      # 빈 화면 안내가 다시 보인다


def test_copy_with_nothing_reports_it(app):
    app.show_command("auto")
    app.clear()
    app.copy()
    assert "없습니다" in app.status.cget("text")
