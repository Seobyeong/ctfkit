"""'다음' 명령이 분야를 잘못 짚지 않기 (실전 기록 5·6) 와 에이전트 모드 start 의 종료 코드.

5: strcmp 로 입력을 비교하는 윈도 PE 에 pwn rop 을 권했다 → pwn rop 은 ELF 에만.
6: 산수 문제를 주고받는 C 서버(위험 함수 없음)에 pwn rop·pwn cyclic 을 권했다 → 소스에 메모리를 넘칠 입력이 없으면 뺀다.
"""

import struct
import zipfile

from ctfkit import source
from ctfkit.cli import main
from ctfkit.commands import start, triage

SAFE_C = """#include <stdio.h>
int main() { int a, b, ans; srand(time(0)); alarm(10);
  for (int i = 0; i < 50; i++) { a = rand(); b = rand(); printf("%d + %d = ?\\n", a, b); scanf("%d", &ans); }
  system("cat flag"); }
"""
RISKY_C = """#include <stdio.h>
int main() { char buf[16]; gets(buf); puts(buf); }
"""


def _elf() -> bytes:
    shoff = 64 + 4
    header = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0, 0, shoff, 0, 64, 56, 0, 64, 1, 0)
    return header + b"code" + b"\x00" * 64


def test_pe_gets_reversing_tips_only():
    tips = triage.next_steps("DOS/PE 실행 파일", "chall.exe")
    assert "rev disasm chall.exe" in tips and not any(t.startswith("pwn rop") for t in tips)
    assert any(t.startswith("pwn rop") for t in triage.next_steps("ELF 실행 파일", "chall"))


def test_c_source_cyclic_only_with_memory_input():
    safe = source.analyze(SAFE_C, "chall.c")
    assert "template pwn <바이너리>" in safe.tips and "pwn cyclic 200" not in safe.tips and not safe.memory
    risky = source.analyze(RISKY_C, "chall.c")
    assert "pwn cyclic 200" in risky.tips and risky.memory


def _start(tmp_path, files, capsys):
    zpath = tmp_path / "chall.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    main(["start", str(zpath), "--root", str(tmp_path / "ws")])
    return capsys.readouterr().out


def test_start_drops_memory_tips_when_source_shows_none(tmp_path, capsys):
    out = _start(tmp_path, {"chall": _elf(), "chall.c": SAFE_C}, capsys)
    tips = [line for line in out.splitlines() if line.startswith("다음:")]
    assert any("template pwn" in t for t in tips)
    assert not any("pwn rop" in t or "pwn cyclic" in t for t in tips)


def test_start_keeps_memory_tips_with_risky_source(tmp_path, capsys):
    out = _start(tmp_path, {"chall": _elf(), "chall.c": RISKY_C}, capsys)
    assert "pwn rop" in out and "pwn cyclic" in out


def test_start_without_source_keeps_elf_tips(tmp_path, capsys):
    out = _start(tmp_path, {"chall": _elf()}, capsys)
    assert "pwn rop" in out


def test_agent_mode_start_exit_code_is_zero_without_flag(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTFKIT_AGENT", "1")
    zpath = tmp_path / "c.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("note.txt", "nothing here\n")
    assert main(["start", str(zpath), "--root", str(tmp_path / "ws")]) == 0
    assert "플래그: 못 찾음" in capsys.readouterr().out
    monkeypatch.setenv("CTFKIT_AGENT", "0")   # 사람용은 그대로 1
    assert main(["start", str(zpath), "--root", str(tmp_path / "ws2")]) == 1
    assert start.agent_mode() is False
