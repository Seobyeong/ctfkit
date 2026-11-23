"""v0.31 AI 에이전트용 요약: 소거(성립하지 않는 공격), 값으로 직접 시도, 값 파일, 소스 압축, AGENTS.md.

에이전트가 소스를 받은 문제에서 가장 많이 쓰는 토큰은 틀린 공격을 시도하는 왕복이다. 여기서 확인하는 것:
  - 코드에 사실로 보이는 것만으로 제외한다. 확실하지 않으면(값을 두 번 넣음, 모드가 변수) 아무 말도 하지 않는다.
  - 줄인 소스는 로직을 건드리지 않는다. 표준과 다른 S-box, 사람이 읽는 문장, 독스트링은 남긴다.
아래 소스는 실제 문제가 아니라 같은 형태로 직접 만든 예제다.
"""

import json
import os
import random
import subprocess
import sys

import pytest

from ctfkit import brief, console, rsautil
from ctfkit.cli import main


@pytest.fixture(autouse=True)
def _reset_quiet():
    console.QUIET = False
    yield
    console.QUIET = False


def _verdicts(text, name="chal.py"):
    sb = brief.analyze_source(text, name)
    return {v.attack: v.status for v in sb.verdicts}


def _next_prime(x: int) -> int:
    x |= 1
    while not rsautil.is_probable_prime(x):
        x += 2
    return x


RSA_STRONG = '''from Crypto.Util.number import getPrime, bytes_to_long
p, q = getPrime(1024), getPrime(1024)
n = p * q
e = 65537
phi = (p - 1) * (q - 1)
m = bytes_to_long(open("flag.txt", "rb").read())
print(n, pow(m, e, n))
'''


# ---------------------------------------------------------------- 소거: RSA

def test_strong_rsa_excludes_attacks_with_line_numbers():
    sb = brief.analyze_source(RSA_STRONG, "chal.py")
    got = {v.attack: v for v in sb.verdicts}
    assert {k for k, v in got.items() if v.status == brief.EXCLUDED} == {
        "작은 e (e제곱근)", "비너 (작은 d)", "페르마 (가까운 소수)", "작은 소인수", "nc 접속 클라이언트"}
    assert got["작은 e (e제곱근)"].lines == (4,)
    assert got["페르마 (가까운 소수)"].where("chal.py") == "chal.py:2"   # 같은 줄은 한 번만
    assert sb.e == 65537
    assert (4, "e = 65537") in sb.facts


def test_next_prime_makes_fermat_a_candidate():
    text = RSA_STRONG.replace("p, q = getPrime(1024), getPrime(1024)", "p = getPrime(1024)\nq = next_prime(p)")
    sb = brief.analyze_source(text)
    fermat = [v for v in sb.verdicts if v.attack.startswith("페르마")][0]
    assert fermat.status == brief.CANDIDATE and fermat.tip == "rsa factor N"


def test_prime_plus_constant_is_not_excluded_as_fermat():
    text = RSA_STRONG.replace("p, q = getPrime(1024), getPrime(1024)",
                              "p = getPrime(1024)\nr = getPrime(1024)\nq = p + 2")
    assert _verdicts(text)["페르마 (가까운 소수)"] == brief.CANDIDATE


def test_custom_prime_search_never_excludes_fermat():
    text = RSA_STRONG.replace("p, q = getPrime(1024), getPrime(1024)",
                              "p, q = getPrime(1024), getPrime(1024)\nwhile not isPrime(q): q += 2")
    assert "페르마 (가까운 소수)" not in _verdicts(text)


def test_reassigned_e_is_unknown_so_no_e_based_verdict():
    text = RSA_STRONG.replace("e = 65537", "e = 65537\nif len(sys.argv) > 1:\n    e = 3")
    got = _verdicts(text)
    assert "작은 e (e제곱근)" not in got and "비너 (작은 d)" not in got
    assert brief.analyze_source(text).e is None


def test_small_e_is_a_candidate_and_e_from_pow_constant():
    assert _verdicts(RSA_STRONG.replace("e = 65537", "e = 3"))["작은 e (e제곱근)"] == brief.CANDIDATE
    no_name = RSA_STRONG.replace("e = 65537\n", "").replace("pow(m, e, n)", "pow(m, 0x10001, n)")
    sb = brief.analyze_source(no_name)
    assert sb.e == 65537 and _verdicts(no_name)["작은 e (e제곱근)"] == brief.EXCLUDED


def test_small_d_makes_wiener_a_candidate():
    text = RSA_STRONG.replace("e = 65537", "d = getPrime(256)\ne = pow(d, -1, (p-1)*(q-1))")
    assert _verdicts(text)["비너 (작은 d)"] == brief.CANDIDATE


def test_syntax_error_or_other_language_gives_no_verdict():
    assert brief.analyze_source("def broken(:\n    pass\n") is None
    assert brief.analyze_source("#include <stdio.h>\nint main(){gets(b);}\n") is None


# ---------------------------------------------------------------- 소거: 블록 암호·난수·입력

AES_ECB_OFFLINE = '''from Crypto.Cipher import AES
import os
key = os.urandom(16)
ct = AES.new(key, AES.MODE_ECB).encrypt(open("flag.txt", "rb").read().ljust(32))
print(ct.hex())
'''

AES_CBC_ORACLE = '''from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
key = get_random_bytes(16)
while True:
    ct = bytes.fromhex(input("ct> "))
    try:
        unpad(AES.new(key, AES.MODE_CBC, ct[:16]).decrypt(ct[16:]), 16)
        print("ok")
    except ValueError:
        print("bad padding")
'''


def test_offline_ecb_excludes_oracles_and_key_search():
    got = _verdicts(AES_ECB_OFFLINE)
    for attack in ("패딩 오라클", "CBC 비트 플립", "ECB 한 바이트씩 복구", "키 전수 조사", "난수 예측", "nc 접속 클라이언트"):
        assert got[attack] == brief.EXCLUDED, attack


def test_cbc_decrypt_oracle_is_a_candidate():
    got = _verdicts(AES_CBC_ORACLE)
    assert got["CBC 비트 플립"] == brief.CANDIDATE
    assert got["패딩 오라클"] == brief.CANDIDATE
    assert got["ECB 한 바이트씩 복구"] == brief.EXCLUDED
    assert got["키 전수 조사"] == brief.EXCLUDED
    assert got["nc 접속 클라이언트"] == brief.CANDIDATE


def test_mode_in_a_variable_is_unknown():
    text = AES_CBC_ORACLE.replace("AES.new(key, AES.MODE_CBC, ct[:16])", "AES.new(key, MODE, ct[:16])")
    sb = brief.analyze_source(text)
    got = {v.attack: v for v in sb.verdicts}
    assert "CBC 비트 플립" not in got and "패딩 오라클" not in got
    # ECB 판정은 모드가 아니라 "암호화 호출이 없다" 는 사실에서 나온다
    assert got["ECB 한 바이트씩 복구"].reason == "암호화 오라클 없음 (encrypt 호출 없음)"


def test_tiny_key_is_a_candidate():
    text = AES_ECB_OFFLINE.replace("os.urandom(16)", "os.urandom(2)")
    assert _verdicts(text)["키 전수 조사"] == brief.CANDIDATE


def test_time_seed_is_a_candidate_and_os_random_alone_is_excluded():
    seeded = "import random, time\nrandom.seed(int(time.time()))\nprint(random.getrandbits(32))\n"
    assert _verdicts(seeded)["난수 예측"] == brief.CANDIDATE
    assert _verdicts("import secrets\nprint(secrets.token_bytes(16))\n")["난수 예측"] == brief.EXCLUDED


def test_web_source_has_no_nc_verdict():
    text = "from flask import Flask, request\napp = Flask(__name__)\n@app.route('/')\ndef i():\n    return request.args['x']\n"
    assert "nc 접속 클라이언트" not in _verdicts(text)


# ---------------------------------------------------------------- 소스 압축

def _sbox_text(values, name="SBOX"):
    return f"{name} = [" + ", ".join(hex(v) for v in values) + "]\n"


def test_standard_sbox_is_replaced_but_modified_one_is_kept():
    box = brief._aes_sbox()
    assert box[:3] == [0x63, 0x7C, 0x77] and box[255] == 0x16
    small = brief.compact(_sbox_text(box) + "print(SBOX[1])\n", "a.py")
    assert "AES 표준 S-box 와 같음, 원본 L1" in small.text and "0x7c" not in small.text
    changed = list(box)
    changed[0], changed[1] = changed[1], changed[0]
    text = _sbox_text(changed) + "print(SBOX[1])\n"
    assert brief.compact(text, "a.py").text == text   # 표준과 다른 S-box 는 취약점일 수 있다


def test_inverse_sbox_and_plain_data_table():
    box = brief._aes_sbox()
    inv = [0] * 256
    for i, v in enumerate(box):
        inv[v] = i
    assert "AES 표준 역 S-box" in brief.compact(_sbox_text(inv, "INV") + "x = INV\n", "a.py").text
    data = brief.compact("CT = [" + ", ".join(str(i * 7) for i in range(100)) + "]\nprint(CT)\n", "a.py").text
    assert "<정수 100개, 처음 0, 7, 14, 원본 L1>" in data


def test_banner_prints_unused_function_and_line_markers():
    text = (
        "import sys\n"                                # 1
        "def unused(a):\n"                            # 2
        "    x = a + 1\n"                             # 3
        "    return x\n"                              # 4
        "def menu():\n"                               # 5
        "    print('=====')\n"                        # 6
        "    print('1. encrypt')\n"                   # 7
        "    print('2. exit')\n"                      # 8
        "    return input('> ')\n"                    # 9
        "menu()\n"                                    # 10
    )
    small = brief.compact(text, "chal.py")
    assert small.text.splitlines() == [
        "import sys",
        "def unused(a):",
        "    ... # [L3-L4 생략: 어디서도 부르지 않는 함수 unused]",
        "def menu():",
        "    # [L6-L8 생략: 글자만 출력하는 print 3개]",
        "    return input('> ')",
        "menu()",
    ]
    assert small.original_lines == 10 and small.kept_lines == 7


def test_dynamic_calls_keep_unused_functions():
    text = "def hidden():\n    return 1\nname = input()\nprint(getattr(__import__('__main__'), name)())\n"
    assert brief.compact(text, "a.py").elided == []
    pickled = "import pickle\ndef gadget():\n    return 1\nprint(pickle.loads(bytes.fromhex(input())))\n"
    assert brief.compact(pickled, "a.py").elided == []


def test_strings_hex_elided_but_prose_and_docstrings_kept():
    prose = "It is a long sentence that might be a hint for the player. " * 5
    text = (f'"""{prose}"""\n'
            f"HINT = {prose!r}\n"
            f"CT = '{'ab' * 150}'\n"
            "print(HINT, CT)\n")
    out = brief.compact(text, "a.py").text
    assert prose in out and "HINT = " + repr(prose) in out
    assert "CT = <hex 300자, 원본 L3>" in out


def test_non_ascii_line_before_literal_keeps_columns():
    text = "메모 = '한글'; T = [" + ", ".join(str(i) for i in range(40)) + "]\nprint(T)\n"
    out = brief.compact(text, "a.py").text
    assert out.startswith("메모 = '한글'; T = <정수 40개, 처음 0, 1, 2, 원본 L1>\n")


def test_c_array_lines_are_elided():
    rows = ["    " + ", ".join(f"0x{i:02x}" for i in range(r, r + 16)) + "," for r in range(0, 64, 16)]
    text = "#include <stdio.h>\nunsigned char key[] = {\n" + "\n".join(rows) + "\n};\nint main(){return 0;}\n"
    small = brief.compact(text, "chal.c")
    assert "// [L3-L6 생략: 숫자 64개가 늘어선 데이터]" in small.text
    assert "int main(){return 0;}" in small.text


# ---------------------------------------------------------------- 값 파일과 직접 시도

def test_extract_and_merge_values():
    found = brief.extract_values("n = 0x10\ne: 3\nc=99 # x\nname = alice\nn = 17\n")
    assert found == [("n", 16, 1), ("e", 3, 2), ("c", 99, 3)]
    store, origins = {}, {}
    brief.merge_values(store, origins, found, "files/a.txt")
    brief.merge_values(store, origins, [("n", 21, 1), ("e", 3, 2)], "files/b.txt")
    assert store == {"n": 16, "e": 3, "c": 99, "n_2": 21}
    assert origins["n_2"] == "files/b.txt:1"


def _rsa(close: bool, seed=7, bits=256):
    rng = random.Random(seed)
    p = _next_prime(rng.getrandbits(bits) | (1 << bits - 1))
    q = _next_prime(p + 2) if close else _next_prime(rng.getrandbits(bits) | (1 << bits - 1))
    return p, q


def test_try_rsa_fermat_small_e_and_shared_prime():
    m = int.from_bytes(b"DH{tried}", "big")
    p, q = _rsa(True)
    tried, plain = brief.try_rsa({"n": p * q, "e": 65537, "c": pow(m, 65537, p * q)})
    assert plain == b"DH{tried}" and tried[-1] == "페르마: 성공"

    p, q = _rsa(False)
    tried, plain = brief.try_rsa({"n": p * q, "c": pow(m, 3, p * q)}, e_hint=3)   # e 는 소스에서
    assert plain == b"DH{tried}" and tried[-1].startswith("작은 e: 성공")

    p2, q2 = _rsa(False, seed=9)
    store = {"n1": p * q, "e": 65537, "c1": pow(m, 65537, p * q), "n2": p * q2}
    tried, plain = brief.try_rsa(store)
    assert plain == b"DH{tried}" and tried[-1] == "다른 n 과 공통 소인수: 성공"


def test_try_rsa_reports_what_it_tried_when_it_fails():
    p, q = _rsa(False)
    tried, plain = brief.try_rsa({"n": p * q, "e": 65537, "c": 12345})
    assert plain is None
    assert tried == [f"작은 소인수 (< {brief.TRIAL_LIMIT}) - 실패", f"페르마 {brief.FERMAT_STEPS}회 - 실패",
                     "비너 - 실패", "factordb 조회는 하지 않음 (네트워크)"]
    assert brief.try_rsa({"n": 15}) == ([], None)   # c 가 없으면 아무것도 하지 않는다


# ---------------------------------------------------------------- start: AGENTS.md

def _challenge(tmp_path, close: bool):
    src_dir = tmp_path / ("close" if close else "strong")
    src_dir.mkdir()
    source = RSA_STRONG if not close else RSA_STRONG.replace(
        "p, q = getPrime(1024), getPrime(1024)", "p = getPrime(1024)\nq = next_prime(p)")
    source = ("def debug(x):\n    print(x)\n    return x\n\n") + source
    (src_dir / "chal.py").write_text(source, encoding="ascii")
    p, q = _rsa(close)
    m = int.from_bytes(b"DH{agents_md}", "big")
    (src_dir / "output.txt").write_text(f"n = {p * q}\ne = 65537\nc = {pow(m, 65537, p * q)}\n", encoding="ascii")
    return src_dir


def test_start_solves_close_primes_from_values(tmp_path, capsys):
    target = _challenge(tmp_path, close=True)
    ws_root = tmp_path / "ws"
    ws_root.mkdir()
    assert main(["start", str(target), "--root", str(ws_root)]) == 0
    out = capsys.readouterr().out
    assert "플래그: DH{agents_md}  [values.json · RSA 페르마]" in out
    ws = ws_root / "close"
    agents = (ws / "AGENTS.md").read_text(encoding="utf-8")
    assert "플래그: DH{agents_md}" in agents
    assert (ws / "CLAUDE.md").read_text(encoding="utf-8") == "@AGENTS.md\n"
    values = json.loads((ws / "values.json").read_text(encoding="utf-8"))
    assert values["e"] == 65537 and values["_from"]["n"] == "files/output.txt:1"


def test_start_strong_rsa_writes_exclusions_and_values_hint(tmp_path, capsys):
    target = _challenge(tmp_path, close=False)
    ws_root = tmp_path / "ws"
    ws_root.mkdir()
    assert main(["start", str(target), "--root", str(ws_root)]) == 1
    out = capsys.readouterr().out
    assert "제외(files/chal.py): 작은 e (e제곱근), 비너 (작은 d), 페르마 (가까운 소수)" in out
    assert "다음: template rsa --values values.json" in out
    assert "forensic strings files/output.txt" not in out    # 값은 values.json 으로 옮겼다
    ws = ws_root / "strong"
    agents = (ws / "AGENTS.md").read_text(encoding="utf-8")
    assert "**ai/chal.py.txt 를 읽을 것**" in agents
    assert "- 페르마 (가까운 소수): 소수를 각각 따로 뽑음 (chal.py:6)" in agents
    assert f"- 페르마 {brief.FERMAT_STEPS}회 - 실패" in agents
    assert "숫자를 스크립트에 옮겨 적지 말고" in agents
    assert str(values_n := json.loads((ws / "values.json").read_text())["n"]) not in agents   # 큰 수를 적지 않는다
    assert values_n.bit_length() > 256
    assert "생략: 어디서도 부르지 않는 함수 debug" in (ws / "ai" / "chal.py.txt").read_text(encoding="utf-8")


def test_start_without_sources_still_writes_agents(tmp_path):
    (tmp_path / "note.txt").write_text("nothing here\n", encoding="ascii")
    ws_root = tmp_path / "ws"
    ws_root.mkdir()
    main(["start", str(tmp_path / "note.txt"), "--root", str(ws_root)])
    agents = (ws_root / "note" / "AGENTS.md").read_text(encoding="utf-8")
    assert "플래그: 못 찾음" in agents and "- files/note.txt:" in agents
    assert not (ws_root / "note" / "values.json").exists() and not (ws_root / "note" / "ai").exists()


# ---------------------------------------------------------------- triage, template, brief 명령

def test_triage_drops_commands_of_excluded_attacks(tmp_path, capsys):
    path = tmp_path / "server.py"
    path.write_text(AES_ECB_OFFLINE.replace("MODE_ECB", "MODE_CBC, iv=os.urandom(16)"), encoding="ascii")
    main(["triage", str(path)])
    out = capsys.readouterr().out
    assert "제외: 패딩 오라클, CBC 비트 플립" in out
    assert "crypto cbc-flip" not in out and "template remote" not in out


def test_template_rsa_reads_values_file(tmp_path, capsys):
    p, q = _rsa(True)
    m = int.from_bytes(b"DH{from_values}", "big")
    store = {"n": p * q, "e": 65537, "c": pow(m, 65537, p * q)}
    brief.write_values(str(tmp_path / "values.json"), store, {})
    script = tmp_path / "solve.py"
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        assert main(["template", "rsa", "--values", "values.json", "-o", str(script)]) == 0
    finally:
        os.chdir(cwd)
    text = script.read_text(encoding="utf-8")
    assert str(p * q) not in text and "V = json.load(open('values.json'))" in text
    run = subprocess.run([sys.executable, str(script)], cwd=tmp_path, capture_output=True, text=True, timeout=60)
    assert "DH{from_values}" in run.stdout


def test_template_rsa_needs_values_or_numbers(tmp_path, capsys):
    assert main(["template", "rsa"]) == 2
    (tmp_path / "v.json").write_text('{"x": 1}', encoding="utf-8")
    assert main(["template", "rsa", "--values", str(tmp_path / "v.json")]) == 2
    assert "n 과 c 가 없습니다" in capsys.readouterr().err


def test_brief_command(tmp_path, capsys):
    src = tmp_path / "chal.py"
    src.write_text(RSA_STRONG, encoding="ascii")
    assert main(["brief", str(src)]) == 0
    out = capsys.readouterr().out
    assert "제외: 페르마 (가까운 소수) - 소수를 각각 따로 뽑음 (chal.py:2)" in out
    assert main(["brief", str(src), "--code"]) == 0
    assert capsys.readouterr().out.startswith("# ctfkit brief: chal.py 7줄 → 7줄.")
    p, q = _rsa(True)
    values = tmp_path / "out.txt"
    values.write_text(f"n = {p * q}\ne = 65537\nc = {pow(5, 65537, p * q)}\n", encoding="ascii")
    assert main(["brief", str(values)]) == 0
    out = capsys.readouterr().out
    assert "값: n(512비트), e=65537, c(" in out and "시도: 페르마: 성공" in out and "평문: b'\\x05'" in out
    c_src = tmp_path / "chal.c"
    c_src.write_text("#include <stdio.h>\nint main(){char b[8]; gets(b);}\n", encoding="ascii")
    assert main(["brief", str(c_src)]) == 1
    assert "성립하지 않는 공격 판정은 파이썬 소스만" in capsys.readouterr().out
