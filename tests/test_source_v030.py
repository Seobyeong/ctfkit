"""v0.30 실전 기록 1: 소스 코드 파일에 strings 검색을 권하던 문제.

암호 문제에서 받은 challenge.py 에 start 가 "forensic strings ... --grep" 을 권했다. 플래그는 서버에 있으므로
쓸모없는 제안이다. 소스를 알아보고 단서(쓰는 라이브러리·입력 여부)와 분야에 맞는 명령을 보여 주게 했다.
아래 소스는 실제 문제가 아니라 같은 형태로 직접 만든 예제다.
"""

import pytest

from ctfkit import console, source
from ctfkit.cli import main
from ctfkit.commands import triage

RSA_SERVER = '''#!/usr/bin/env python3
from Crypto.Util.number import getPrime, bytes_to_long

p, q = getPrime(1024), getPrime(1024)
n = p * q
e = 65537
m = bytes_to_long(open("./flag.txt", "rb").read())

def encrypt(x):
    return pow(x, e, n)

print(n, encrypt(m))
cmd = input("> ")
'''

AES_CBC = '''from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
key = b"k" * 16
def decrypt(ct):
    return unpad(AES.new(key, AES.MODE_CBC, ct[:16]).decrypt(ct[16:]), 16)
'''

FLASK_APP = '''from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route("/")
def index():
    return "hi"

@app.route("/hello", methods=["GET"])
def hello():
    return render_template_string("Hello " + request.args.get("name", ""))
'''

PWN_C = '''#include <stdio.h>
int main() {
    char buf[32];
    gets(buf);
    printf(buf);
    return 0;
}
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


def test_rsa_server_clues_and_tips():
    info = source.analyze(RSA_SERVER, "challenge.py")
    assert info.lang == "Python"
    for clue in ("RSA·정수 암호", "소수 1024비트", "e=65537", "플래그 파일 ./flag.txt", "함수 encrypt"):
        assert clue in info.clues
    assert any(c.startswith("입력을 받음") for c in info.clues)
    assert info.tips[0].startswith("rsa decrypt")
    assert any(t.startswith("template rsa") for t in info.tips)


def test_aes_cbc_suggests_cbc_flip():
    info = source.analyze(AES_CBC, "chal.py")
    assert "블록·스트림 암호 AES" in info.clues and "모드 CBC" in info.clues and "패딩 처리" in info.clues
    assert any(t.startswith("crypto cbc-flip") for t in info.tips)


def test_flask_routes_and_risky_function():
    info = source.analyze(FLASK_APP, "app.py")
    assert "웹 서버 Flask" in info.clues
    assert "경로 /, /hello" in info.clues
    assert "위험 함수 render_template_string" in info.clues
    assert info.tips == ["template web URL"]


def test_c_source_dangerous_functions():
    info = source.analyze(PWN_C, "chall.c")
    assert info.lang == "C"
    assert "위험 함수 gets, printf(변수)" in info.clues
    assert "template pwn <바이너리>" in info.tips


def test_language_from_content_without_extension():
    assert source.language(RSA_SERVER, "challenge") == "Python"
    assert source.language(PWN_C, "noext") == "C"
    assert source.language("<?php echo 1; ?>", "index") == "PHP"


def test_plain_text_is_not_source():
    assert source.analyze("just a memo about the weather\nnothing here\n", "memo.txt") is None
    assert source.analyze("ZmxhZ3t0ZXN0fQ==", "data.txt") is None


def test_triage_uses_source_tips_instead_of_strings(tmp_path, capsys):
    path = tmp_path / "challenge.py"
    path.write_text(RSA_SERVER, encoding="utf-8")
    code, out, _ = _run(capsys, "triage", str(path), "--no-external")
    assert code == 1
    assert "소스: Python" in out and "단서: RSA·정수 암호" in out
    next_line = next(line for line in out.splitlines() if line.startswith("다음: "))
    # v0.30 실전 기록 3: 입력을 받는 서버 소스는 template remote 를 먼저 권한다
    assert next_line.startswith("다음: template remote ") and "rsa decrypt" in next_line
    assert "forensic strings" not in out
    assert "내용: " not in out   # 소스는 첫 줄 미리보기 대신 단서를 보여 준다


def test_source_without_specific_tips_falls_back_to_strings():
    info = source.analyze("import os\nprint(os.getcwd())\n", "x.py")
    assert info.tips == []
    tips = triage.next_steps("글자 파일", "x.py", info)
    assert tips == ["forensic strings x.py --grep <정규식>"]


def test_flag_in_source_comment_still_found(tmp_path, capsys):
    path = tmp_path / "chal.py"
    path.write_text("# DH{in_a_comment}\nimport os\n", encoding="utf-8")
    code, out, _ = _run(capsys, "triage", str(path), "--no-external")
    assert code == 0 and "DH{in_a_comment}" in out


def test_start_on_zip_with_source(tmp_path, capsys):
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("challenge.py", RSA_SERVER)
    archive = tmp_path / "abc (1).zip"
    archive.write_bytes(buf.getvalue())
    code, out, _ = _run(capsys, "start", str(archive), "--root", str(tmp_path / "ws"), "--no-external")
    assert code == 1
    assert "단서 RSA·정수 암호" in out
    assert "다음: rsa decrypt" in out and "forensic strings" not in out
    assert (tmp_path / "ws" / "abc" / "notes.md").exists()
