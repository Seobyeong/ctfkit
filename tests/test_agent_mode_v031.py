"""에이전트 모드와 실행 환경 안내 (실행 기록 분석에서 나온 두 가지).

- 에이전트는 start 출력을 읽고 곧바로 AGENTS.md 를 또 열었다 → 에이전트 셸이면 start 가 AGENTS.md 를 바로 출력한다.
- python3·strings 가 없거나 콘솔이 cp949 라서 실행마다 1~1.5번 왕복을 버렸다 → AGENTS.md 에 실행 환경을 적는다.
"""

import base64

from ctfkit.cli import main
from ctfkit.commands import start


def _chall(tmp_path, data=b"nothing to see here\n"):
    chall = tmp_path / "chall"
    chall.mkdir()
    (chall / "a.txt").write_bytes(data)
    return chall


def test_agent_mode_detection(monkeypatch):
    for name in ("CTFKIT_AGENT", "CLAUDECODE", "AI_AGENT"):
        monkeypatch.delenv(name, raising=False)
    assert not start.agent_mode()
    monkeypatch.setenv("CLAUDECODE", "1")
    assert start.agent_mode()
    monkeypatch.setenv("CTFKIT_AGENT", "0")   # 직접 끈 것이 우선
    assert not start.agent_mode()
    monkeypatch.delenv("CTFKIT_AGENT")
    monkeypatch.delenv("CLAUDECODE")
    monkeypatch.setenv("AI_AGENT", "codex")
    assert start.agent_mode()


def test_agent_mode_prints_agents_md_instead_of_file_list(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTFKIT_AGENT", "1")
    # 플래그를 못 찾아도 0: 에이전트는 1 을 "명령 실패" 로 읽었다. 못 찾음은 첫 줄에 있다
    assert main(["start", str(_chall(tmp_path)), "--root", str(tmp_path / "ws")]) == 0
    out = capsys.readouterr().out
    assert "플래그: 못 찾음" in out
    agents = (tmp_path / "ws" / "chall" / "AGENTS.md").read_text(encoding="utf-8")
    assert "에이전트 모드" in out and agents in out
    assert "노트:" not in out and "AI 요약:" not in out   # 사람용 줄은 없다


def test_agent_mode_with_flag_keeps_flag_and_evidence(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTFKIT_AGENT", "1")
    data = base64.b64encode(b"DH{agent_mode_flag}") + b"\n"
    assert main(["start", str(_chall(tmp_path, data)), "--root", str(tmp_path / "ws")]) == 0
    out = capsys.readouterr().out
    assert "플래그: DH{agent_mode_flag}" in out and "근거:" in out


def test_environment_lines_only_when_something_is_off(monkeypatch):
    monkeypatch.undo()   # conftest 가 빈 목록으로 바꿔 둔 것을 되돌린다
    tools = {"python3": "/usr/bin/python3", "python": "/usr/bin/python", "strings": "/usr/bin/strings",
             "file": "/usr/bin/file", "binwalk": "/usr/bin/binwalk"}
    monkeypatch.setattr(start.shutil, "which", lambda name: tools.get(name))
    monkeypatch.setattr(start.locale, "getpreferredencoding", lambda do_setlocale=True: "UTF-8")
    monkeypatch.setattr(start.os, "name", "posix")
    assert start.environment_lines() == []

    tools["python3"] = r"C:\Users\x\AppData\Local\Microsoft\WindowsApps\python3.exe"
    tools.pop("strings")
    monkeypatch.setattr(start.locale, "getpreferredencoding", lambda do_setlocale=True: "cp949")
    monkeypatch.setattr(start.os, "name", "nt")
    lines = "\n".join(start.environment_lines())
    assert "윈도우" in lines and "Microsoft Store" in lines and "cp949" in lines and "-X utf8" in lines
    assert "strings → `ctfkit forensic strings FILE`" in lines and "binwalk" not in lines


def test_agents_md_has_environment_section(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(start, "environment_lines", lambda: ["- 콘솔 인코딩이 cp949 이다"])
    main(["start", str(_chall(tmp_path)), "--root", str(tmp_path / "ws")])
    agents = (tmp_path / "ws" / "chall" / "AGENTS.md").read_text(encoding="utf-8")
    assert "## 실행 환경\n- 콘솔 인코딩이 cp949 이다" in agents


def test_short_files_are_inlined_only_when_no_flag(tmp_path, capsys):
    chall = tmp_path / "chall"
    chall.mkdir()
    (chall / "prob.py").write_text("import random\nrandom.seed(1)\nprint(random.getrandbits(32))\n", encoding="utf-8")
    (chall / "out.txt").write_text("2746317213\n", encoding="utf-8")
    (chall / "big.txt").write_text("x" * (start.INLINE_FILE + 1), encoding="utf-8")
    (chall / "blob.bin").write_bytes(bytes(range(256)) * 2)
    main(["start", str(chall), "--root", str(tmp_path / "ws")])
    agents = (tmp_path / "ws" / "chall" / "AGENTS.md").read_text(encoding="utf-8")
    section = agents.split("## 원문", 1)[1]
    assert "### files/prob.py\n```\nimport random\n" in section and "### files/out.txt\n```\n2746317213\n```" in section
    assert "big.txt" not in section and "blob.bin" not in section
    assert section.index("prob.py") < section.index("out.txt")   # 소스가 먼저

    solved = tmp_path / "solved"
    solved.mkdir()
    (solved / "a.txt").write_bytes(base64.b64encode(b"DH{inline_not_needed}") + b"\n")
    main(["start", str(solved), "--root", str(tmp_path / "ws")])
    assert "## 원문" not in (tmp_path / "ws" / "solved" / "AGENTS.md").read_text(encoding="utf-8")
