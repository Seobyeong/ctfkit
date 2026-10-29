"""workspace 명령 테스트. --root 로 임시 폴더를 가리켜 격리한다."""

import os

from ctfkit.cli import main


def test_new_creates_folder_and_notes(tmp_path, capsys):
    assert main(["workspace", "--root", str(tmp_path), "new", "prob1"]) == 0
    assert os.path.isfile(tmp_path / "prob1" / ".ctfkit-workspace")
    notes = (tmp_path / "prob1" / "notes.md").read_text(encoding="utf-8")
    assert "prob1" in notes


def test_new_duplicate_fails(tmp_path, capsys):
    main(["workspace", "--root", str(tmp_path), "new", "p"])
    assert main(["workspace", "--root", str(tmp_path), "new", "p"]) == 1
    assert "이미 있는" in capsys.readouterr().err


def test_list_shows_workspaces(tmp_path, capsys):
    main(["workspace", "--root", str(tmp_path), "new", "alpha"])
    main(["workspace", "--root", str(tmp_path), "new", "beta"])
    capsys.readouterr()
    assert main(["workspace", "--root", str(tmp_path), "list"]) == 0
    out = capsys.readouterr().out
    assert "alpha" in out and "beta" in out


def test_list_empty(tmp_path, capsys):
    assert main(["workspace", "--root", str(tmp_path), "list"]) == 1


def test_log_appends(tmp_path, capsys):
    main(["workspace", "--root", str(tmp_path), "new", "p"])
    assert main(["workspace", "--root", str(tmp_path), "log", "p", "ctfkit", "auto", "xyz"]) == 0
    log = (tmp_path / "p" / "commands.log").read_text(encoding="utf-8")
    assert "ctfkit auto xyz" in log


def test_log_unknown_workspace(tmp_path, capsys):
    assert main(["workspace", "--root", str(tmp_path), "log", "nope", "cmd"]) == 1
    assert "작업 폴더가 아닙니다" in capsys.readouterr().err


def test_info(tmp_path, capsys):
    main(["workspace", "--root", str(tmp_path), "new", "p"])
    main(["workspace", "--root", str(tmp_path), "log", "p", "cmd1"])
    capsys.readouterr()
    assert main(["workspace", "--root", str(tmp_path), "info", "p"]) == 0
    out = capsys.readouterr().out
    assert "명령 기록: 1개" in out


def test_alias_ws(tmp_path, capsys):
    assert main(["ws", "--root", str(tmp_path), "new", "p"]) == 0
