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


# --- 사용 편의 (화면별 결과, 입력 문제 안내, 예시, 결과 보내기, 설명 풍선) ---

from ctfkit.gui.app import LINE, RED  # noqa: E402


def _run_example(app, command, action=None):
    app.show_command(command)
    if action:
        app.show_action(action)
    app.fill_example()
    app.run()
    _wait(app)


def test_result_stays_with_the_screen_that_ran_it(app):
    _run_example(app, "auto")
    assert app.flags == ["DH{preview_multi_layer}"]
    app.show_command("hash")
    # 다른 화면에는 auto 의 결과·플래그·명령줄이 따라오지 않는다
    assert _output(app) == "" and app.flags == []
    assert not app.flag_bar.winfo_manager()
    assert app.cmd_var.get() == ""
    assert "대기" in app.status.cget("text")
    app.show_command("auto")
    # 돌아오면 그대로 있다
    assert "DH{preview_multi_layer}" in _output(app)
    assert app.flag_bar.winfo_manager() == "pack"
    assert app.out.tag_ranges("flag")
    assert "완료" in app.status.cget("text")


def test_each_tab_keeps_its_own_result(app):
    _run_example(app, "hash", "id")
    assert "md5" in _output(app)
    app.show_action("sum")
    assert _output(app) == ""
    app.show_action("id")
    assert "md5" in _output(app)


def test_output_arrives_while_looking_at_another_screen(app):
    app.show_command("auto")
    app.fill_example()
    app.run()
    app.show_command("hash")           # 실행 중에 다른 화면으로 옮긴다
    _wait(app)
    assert _output(app) == ""          # 지금 화면에는 섞여 들어오지 않는다
    assert "자동 해독" in app.status.cget("text")   # 어느 화면의 작업이 끝났는지 알려 준다
    app.show_command("auto")
    assert "DH{preview_multi_layer}" in _output(app)


def test_missing_required_field_is_marked_and_focused(app):
    app.show_command("hash")
    app.show_action("crack")
    app.run()
    assert app.job is None
    assert "해시값" in app.problem.cget("text")
    assert app.inputs["digest"].cget("highlightbackground") == RED
    assert app.marked is app.inputs["digest"]
    app.set_values({"digest": "abc"})
    app.run()                           # 이제 다음 빠진 항목(워드리스트)으로 옮겨 간다
    assert app.inputs["digest"].cget("highlightbackground") == LINE
    assert app.marked is app.inputs["words"]


def test_problem_message_clears_when_leaving_the_screen(app):
    app.show_command("hash")
    app.show_action("crack")
    app.run()
    app.show_command("auto")
    assert app.problem.cget("text") == ""
    assert "대기" in app.status.cget("text")   # 다른 화면의 오류가 상태 줄에 남지 않는다


def test_problem_in_folded_option_unfolds_it(app):
    app.show_command("auto")
    app.set_values({"data": "abc", "depth": "many"})
    app._set_folded(True, 4)
    app.run()
    assert app.job is None
    assert app.expanded[("auto", None)]
    assert app.marked is app.inputs["depth"]
    app.set_values({"depth": "6"})


def test_example_link_only_where_an_example_exists(app):
    app.show_command("auto")
    assert app.example_link.winfo_manager() == "pack"
    assert "예시" in app.hint.cget("text")
    app.show_command("triage")          # 파일이 필요한 화면에는 예시가 없다
    assert not app.example_link.winfo_manager()
    assert "예시" not in app.hint.cget("text")


def test_fill_example_keeps_other_values(app):
    app.show_command("crack")
    app.set_values({"top": "9"})
    app.fill_example()
    values = app.values()
    assert values["data"].startswith("Wkh txlfn") and values["transform"] == "caesar"
    assert values["top"] == "9"
    app.set_values({"top": "5"})


def test_stop_button_only_visible_while_running(app):
    app.show_command("auto")
    assert not app.stop_btn.winfo_manager()
    app.fill_example()
    app.run()
    assert app.stop_btn.winfo_manager() == "pack"
    _wait(app)
    assert not app.stop_btn.winfo_manager()


def test_send_result_to_another_tool(app):
    _run_example(app, "codec", "decode")
    assert _output(app).strip() == "DH{hello_ctfkit}"
    targets = {(c, a): dest for _, c, a, dest in app.send_targets()}
    assert targets[("auto", None)] == "data" and ("triage", None) not in targets
    app.send_to("crack", None, "data")
    assert app.command.name == "crack"
    assert app.values()["data"] == "DH{hello_ctfkit}"
    assert _output(app) == ""           # 새 입력과 맞지 않는 예전 결과는 비운다


def test_send_with_no_result_reports_it(app):
    app.show_command("base")
    app.clear()
    app.send_to("auto", None, "data")
    assert app.command.name == "base"
    assert "보낼 결과가 없습니다" in app.status.cget("text")


def test_labels_carry_help_as_tooltip(app):
    app.show_command("pwn")
    app.show_action("cyclic")
    texts = [tip.text for tip in app.tips]
    assert any("리틀엔디언" in t for t in texts)        # 라벨에서 뺀 형식 예시가 설명에 남아 있다
    tip = app.tips[0]
    tip.show()
    assert tip.tip is not None
    tip.hide()
    assert tip.tip is None


def test_no_gap_left_when_command_has_no_tabs(app):
    app.show_command("hash")            # 탭이 있는 화면
    app.root.update_idletasks()
    app.show_command("auto")            # 탭이 없는 화면
    app.root.update_idletasks()
    assert app.tabs.winfo_reqheight() <= 2
