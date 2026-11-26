"""플래그를 못 찾았을 때 AGENTS.md 에 "ctfkit 이 이미 확인함" 을 적는다.

근거: 실행 기록에서 에이전트는 ctfkit 이 이미 본 파일을 다시 열고 strings·디코딩을 다시 돌렸다. 돌린 검사만, 범위와 함께 적는다.
"""

import zipfile

from ctfkit.cli import main
from ctfkit.commands import start, triage

TITLE = "## ctfkit 이 이미 확인함"


def _agents(tmp_path, files):
    source = tmp_path / "chall.zip"
    with zipfile.ZipFile(source, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    main(["start", str(source), "--root", str(tmp_path / "ws"), "--name", "c"])
    return (tmp_path / "ws" / "c" / "AGENTS.md").read_text(encoding="utf-8")


def _section(agents):
    return agents.split(TITLE, 1)[1].split("\n## ", 1)[0]


def test_lists_checks_that_ran(tmp_path, capsys):
    agents = _agents(tmp_path, {"pic.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 300,
                                "blob.bin": bytes(range(256)) * 3})
    section = _section(agents)
    assert f"- {triage.CHECK_SCAN}: 모든 파일" in section
    assert f"- {triage.CHECK_EMBEDDED}: 모든 파일" in section
    assert f"- {triage.CHECK_XOR}: blob.bin" in section          # 형식을 모르는 파일에만 돌린 검사
    assert "pic.png" not in section.split(triage.CHECK_XOR)[1].splitlines()[0]


def test_not_written_when_flag_found(tmp_path, capsys):
    agents = _agents(tmp_path, {"a.txt": "flag{real_one}\n"})
    assert TITLE not in agents


def test_hidden_file_is_not_called_checked(tmp_path, capsys):
    # 숨은 파일이 보이면 "시그니처 확인: 없음" 이라 적지 않는다
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    agents = _agents(tmp_path, {"a.bin": b"\x01\x02junk" * 20 + png})
    assert triage.CHECK_EMBEDDED not in agents


def test_same_basename_keeps_paths(tmp_path, capsys):
    agents = _agents(tmp_path, {"a/out.bin": bytes(range(200)), "b/out.bin": bytes(range(1, 201)),
                                "c.txt": "nothing here\n"})
    line = next(l for l in _section(agents).splitlines() if l.startswith(f"- {triage.CHECK_XOR}"))
    assert "a/out.bin" in line and "b/out.bin" in line


def test_external_tool_recorded_only_when_run(monkeypatch):
    report = triage.Report(triage.compile_pattern(None))

    class Result:
        usable, output, text = True, b"", ""

    monkeypatch.setattr(triage.external, "run", lambda name, args: Result())
    triage._ext_binwalk("x", report)
    assert report.checked == [triage.CHECK_EXTERNAL["binwalk"]]
    Result.usable = False
    triage._ext_zsteg("x", report)
    assert triage.CHECK_EXTERNAL["zsteg"] not in report.checked


def test_missing_tools_listed():
    entry = start.Entry("x.png")
    entry.report = triage.Report(triage.compile_pattern(None))
    entry.report.check(triage.CHECK_SCAN)
    entry.report.missing = ["zsteg"]
    lines = start._checked_lines([entry])
    assert f"- {triage.CHECK_SCAN}: x.png" in lines and "- 못 함 (설치 안 됨): zsteg" in lines
