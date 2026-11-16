"""v0.30 실전 기록 1·3: nc 로 접속하는 문제 (서버 소스만 주는 암호 문제).

세 문제 중 두 문제가 서버 소스를 주고 nc 로 접속하게 했다. 서버 소스에서 주고받는 순서를 읽어 소켓 스크립트를
만드는 template remote 를 만들었다. 아래 서버는 실제 문제가 아니라 같은 형태로 직접 만든 예제다.
"""

import socket
import threading

import pytest

from ctfkit import console, source
from ctfkit.cli import main
from ctfkit.commands import template, triage

SERVER = '''#!/usr/bin/env python3
import os, signal
signal.alarm(30)
secret = os.urandom(2)
print(f"Token: {secret.hex()}")
while True:
    print("[1] Guess")
    print("[2] Quit")
    choice = input("> ")
    if choice == "1":
        guess = input("Your guess (hex): ")
        if bytes.fromhex(guess) == secret:
            print(open("flag").read())
    else:
        break
'''


@pytest.fixture(autouse=True)
def _reset_quiet():
    console.QUIET = False
    yield
    console.QUIET = False


def _run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def test_server_steps_in_source_order():
    steps = template.server_steps(SERVER)
    assert [(kind, prefix) for kind, prefix, _ in steps] == [
        ("value", b"Token: "), ("input", b"> "), ("input", b"Your guess (hex): ")]


def test_server_steps_non_python_is_empty():
    assert template.server_steps("int main() { gets(buf); }") == []


def test_render_remote_is_valid_python_with_clues():
    script = template.render_remote("chal.py", SERVER, "host3.example", 9000)
    compile(script, "solve.py", "exec")
    assert "HOST = 'host3.example'" in script and "PORT = 9000" in script
    assert "서버 시간 제한 30초" in script
    assert "무작위 2바이트" in script
    assert "v1 = value_after(io, b'Token: ')" in script
    assert "io.recvuntil(b'Your guess (hex): ')" in script


def test_prompt_with_quotes_does_not_break_script():
    script = template.render_remote("x.py", 'input("it\'s \\"quoted\\" > ")\nprint(f"a\'b {1}")\n')
    compile(script, "solve.py", "exec")


def test_generated_client_talks_to_a_server():
    # 생성된 Remote·value_after 가 실제 소켓에서 동작하는지 (접속은 이 테스트가 띄운 로컬 서버에만)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    received = []

    def serve():
        conn, _ = listener.accept()
        with conn:
            conn.sendall(b"Token: ab12\n> ")
            received.append(conn.recv(100))
            conn.sendall(b"DH{remote_ok}\n")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    namespace = {"__name__": "solve"}
    exec(template.render_remote("chal.py", SERVER, "127.0.0.1", port), namespace)
    io = namespace["Remote"]("127.0.0.1", port, timeout=5)
    assert namespace["value_after"](io, b"Token: ") == "ab12"
    io.recvuntil(b"> ")
    io.sendline("1")
    assert b"DH{remote_ok}" in io.recvall()
    thread.join(5)
    listener.close()
    assert received == [b"1\n"]


def test_cli_writes_file(tmp_path, capsys):
    src = tmp_path / "prob.py"
    src.write_text(SERVER, encoding="utf-8")
    out = tmp_path / "solve.py"
    code, _, err = _run(capsys, "template", "remote", str(src), "--port", "1234", "-o", str(out))
    assert code == 0 and out.exists() and "저장" in err
    code, _, err = _run(capsys, "template", "remote", str(src), "-o", str(out))
    assert code == 2 and "이미 있는 파일" in err


def test_cli_missing_source_is_short_error(capsys):
    code, out, err = _run(capsys, "template", "remote", "no_such.py")
    assert code == 2 and out == "" and err.startswith("오류: ")


def test_source_clues_for_server():
    info = source.analyze(SERVER, "chal.py")
    assert info.remote
    assert "시간 제한 30초" in info.clues and "무작위 2바이트" in info.clues


def test_double_cipher_count_clue():
    text = "from Crypto.Cipher import DES\nc1 = DES.new(k1, DES.MODE_ECB)\nc2 = DES.new(k2, DES.MODE_ECB)\n"
    assert "암호 객체 2개" in source.analyze(text, "p.py").clues


def test_next_steps_suggest_template_remote_first():
    info = source.analyze(SERVER, "chal.py")
    assert triage.next_steps("글자 파일", "x/chal.py", info)[0] == "template remote x/chal.py --host HOST --port PORT"


def test_c_server_does_not_get_python_remote_template():
    info = source.analyze("#include <stdio.h>\nint main(){ char b[8]; gets(b); }\n", "c.c")
    assert not any(t.startswith("template remote") for t in triage.next_steps("글자 파일", "c.c", info))


@pytest.mark.parametrize("given, port, expected", [
    ("http://host3.dreamhack.games:17980/", 0, ("host3.dreamhack.games", 17980)),
    ("host3.dreamhack.games:17980", 0, ("host3.dreamhack.games", 17980)),
    ("nc host3.dreamhack.games 17980", 0, ("host3.dreamhack.games", 17980)),
    ("host3.dreamhack.games", 17980, ("host3.dreamhack.games", 17980)),
    ("http://host3.dreamhack.games:17980/", 1234, ("host3.dreamhack.games", 1234)),
    ("localhost", 0, ("localhost", 0)),
])
def test_split_address(given, port, expected):
    # 실전 기록 3: 드림핵 화면의 주소를 그대로 붙여 넣는 경우
    assert template.split_address(given, port) == expected


def test_cli_accepts_full_url_as_host(tmp_path, capsys):
    src = tmp_path / "prob.py"
    src.write_text(SERVER, encoding="utf-8")
    code, out, _ = _run(capsys, "template", "remote", str(src), "--host", "http://host3.dreamhack.games:17980/")
    assert code == 0
    assert "HOST = 'host3.dreamhack.games'" in out and "PORT = 17980" in out
