"""v0.28 풀이 뼈대: template pwn / web / rsa.

Gate: 생성된 스크립트가 compile() 로 파싱되고, 분석으로 알아낸 값(아키텍처, PIE, 카나리)이 들어가 있다.
pwntools·requests 는 CI 에 없으므로 pwn·web 은 파싱까지만, 표준 라이브러리만 쓰는 rsa 는 실제로 실행해 평문을 확인한다.
"""

import subprocess
import sys

import pytest

from ctfkit import console
from ctfkit.cli import main
from ctfkit.commands import template
from ctfkit.rsautil import is_probable_prime
from tests.test_pwn import _build_elf


@pytest.fixture(autouse=True)
def _reset_quiet():
    console.QUIET = False
    yield
    console.QUIET = False


def _run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def _parses(source: str) -> None:
    compile(source, "solve.py", "exec")


FACTS = {
    "arch": "amd64", "bits": 64, "endian": "little", "pie": False, "canary": False, "nx": True,
    "relro": "Partial RELRO", "wins": ["win"], "overflow": ["gets"], "format": [], "system": False,
    "addrs": {"win": 0x401196, "main": 0x4011c0, "gets": 0},
}


# --------------------------------------------------------------- pwn

@pytest.mark.parametrize("pie,canary,nx,relro", [
    (False, False, False, "none"),
    (True, True, True, "full"),
    (False, True, True, "partial"),
])
def test_pwn_script_has_analyzed_values(tmp_path, capsys, pie, canary, nx, relro):
    path = tmp_path / "chall"
    path.write_bytes(_build_elf(pie=pie, nx=nx, canary=canary, relro=relro))
    code, out, _ = _run(capsys, "template", "pwn", str(path))
    assert code == 0
    _parses(out)
    assert "ARCH = 'amd64'" in out and "context.binary = elf = ELF(BINARY" in out
    assert f"PIE = {pie}" in out
    assert f"CANARY = {canary}" in out
    assert f"NX = {nx}" in out
    assert f"RELRO = {dict(none='No RELRO', full='Full RELRO', partial='Partial RELRO')[relro]!r}" in out
    assert out.startswith("#!/usr/bin/env python3\n# ctfkit ") and "pip install pwntools" in out


def test_pwn_hints_follow_protections():
    script = template.render_pwn("chall", dict(FACTS, nx=False))
    _parses(script)
    assert "elf.sym['win'],   # 0x401196" in script     # PIE 꺼짐: 주소를 바로 쓴다
    assert "gets: 스택 오버플로 후보" in script.replace("입력 함수 ", "")
    assert "셸코드" in script
    assert "GOT 덮어쓰기" in script

    pie = template.render_pwn("chall", dict(FACTS, pie=True, canary=True))
    assert "elf.sym['win']" not in pie and "주소 유출" in pie
    assert "카나리를 유출" in pie


def test_pwn_paths_are_quoted_safely(tmp_path, capsys):
    path = tmp_path / "it's chall"
    path.write_bytes(_build_elf())
    code, out, _ = _run(capsys, "template", "pwn", str(path), "--host", "a'b", "--port", "31337")
    assert code == 0
    _parses(out)
    assert "31337" in out
    # 윈도 파일 이름에 쓸 수 없는 문자도 (리눅스에서는 가능) 문법을 깨지 않는다
    _parses(template.render_pwn('x"\'\\\n.bin', FACTS, host='"', libc="l'ibc", ld='l"d'))


def test_symbol_names_cannot_inject_code():
    # 출제자가 심볼 이름에 줄바꿈을 넣어 생성된 스크립트에 코드를 심으려는 경우
    # 테스트용 ELF 의 심볼 "main" 을 같은 길이의 다른 이름으로 바꾼다
    good = template.pwn_facts(_build_elf(pie=False).replace(b"main\x00", b"win\x00\x00", 1))
    assert good["wins"] == ["win"]
    assert "elf.sym['win']" in template.render_pwn("chall", good)

    evil = template.pwn_facts(_build_elf(pie=False).replace(b"main\x00", b"win\n\x00", 1))
    assert all("\n" not in name for name in evil["addrs"])
    assert evil["wins"] == []


def test_pwn_uses_bundled_libc_and_loader(tmp_path, capsys):
    (tmp_path / "chall").write_bytes(_build_elf())
    (tmp_path / "libc.so.6").write_bytes(b"x")
    (tmp_path / "ld-linux-x86-64.so.2").write_bytes(b"x")
    script = template.render_pwn("chall", FACTS, libc="./libc.so.6", ld="./ld-linux-x86-64.so.2")
    _parses(script)
    assert "libc = ELF('./libc.so.6'" in script
    assert "process(['./ld-linux-x86-64.so.2', BINARY]" in script
    assert template._libs(str(tmp_path / "chall"))[0].endswith("/libc.so.6")


def test_pwn_rejects_non_elf(tmp_path, capsys):
    path = tmp_path / "x.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    code, _, err = _run(capsys, "template", "pwn", str(path))
    assert code == 2


def test_output_file_not_overwritten_without_force(tmp_path, capsys):
    elf = tmp_path / "chall"
    elf.write_bytes(_build_elf())
    out = tmp_path / "solve.py"
    assert _run(capsys, "template", "pwn", str(elf), "-o", str(out))[0] == 0
    _parses(out.read_text(encoding="utf-8"))

    out.write_text("# my work")
    code, _, err = _run(capsys, "template", "pwn", str(elf), "-o", str(out))
    assert code == 2 and "--force" in err
    assert out.read_text() == "# my work"
    assert _run(capsys, "template", "pwn", str(elf), "-o", str(out), "--force")[0] == 0
    assert "from pwn import *" in out.read_text(encoding="utf-8")


# --------------------------------------------------------------- web

def test_web_script(capsys):
    code, out, _ = _run(capsys, "template", "web", "http://host1.dreamhack.games:12345/")
    assert code == 0
    _parses(out)
    assert "BASE = 'http://host1.dreamhack.games:12345'" in out
    assert "requests.Session()" in out and "pip install requests" in out


def test_web_requires_http_url(capsys):
    assert _run(capsys, "template", "web", "host1.dreamhack.games")[0] == 2


# --------------------------------------------------------------- rsa

def _next_prime(x: int) -> int:
    while not is_probable_prime(x):
        x += 1
    return x


def _run_script(tmp_path, source: str) -> str:
    path = tmp_path / "solve.py"
    path.write_text(source, encoding="utf-8")
    proc = subprocess.run([sys.executable, "-I", str(path)], capture_output=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.decode()


def test_rsa_script_solves_small_e(tmp_path, capsys):
    m = int.from_bytes(b"DH{cube_root}", "big")
    n = _next_prime(1 << 1024) * _next_prime(1 << 1030)
    c = pow(m, 3, n)
    code, out, _ = _run(capsys, "template", "rsa", "-n", str(n), "-e", "3", "-c", hex(c))
    assert code == 0
    assert f"n = {n}" in out and "e = 3" in out and f"c = {c}" in out
    assert "정확히 떨어진다" in out
    assert "DH{cube_root}" in _run_script(tmp_path, out)


def test_rsa_script_solves_close_primes(tmp_path, capsys):
    p = _next_prime(3 ** 200)
    q = _next_prime(p + 10 ** 6)
    n, e = p * q, 65537
    c = pow(int.from_bytes(b"DH{fermat}", "big"), e, n)
    code, out, _ = _run(capsys, "template", "rsa", "-n", str(n), "-c", str(c))
    assert code == 0
    assert "DH{fermat}" in _run_script(tmp_path, out)


def test_rsa_wiener_hint():
    notes = template.rsa_notes(n=(1 << 512) + 1, e=(1 << 500) + 1, c=5)
    assert any("비너" in note for note in notes)


def test_rsa_bad_values(capsys):
    assert _run(capsys, "template", "rsa", "-n", "abc", "-c", "1")[0] == 2
    assert _run(capsys, "template", "rsa", "-n", "1", "-c", "1")[0] == 2


# --------------------------------------------------------------- triage·start 안내

def test_triage_and_start_suggest_template_for_elf(tmp_path, capsys):
    elf = tmp_path / "chall"
    elf.write_bytes(_build_elf())
    code, out, _ = _run(capsys, "triage", str(elf))
    assert code == 1 and "template pwn" in out

    code, out, _ = _run(capsys, "start", str(elf), "--root", str(tmp_path / "ws"))
    assert "다음: template pwn files/chall" in out
    notes = (tmp_path / "ws" / "chall" / "notes.md").read_text(encoding="utf-8")
    assert "`ctfkit template pwn files/chall`" in notes
