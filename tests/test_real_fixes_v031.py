"""실제 문제 측정에서 start 가 못 푼 세 모양 (같은 모양의 직접 만든 예제로 검사한다).

1. 출력 파일에 hex 로 적은 바이트 시저
2. 소스가 정한 62글자 알파벳(대문자+소문자+숫자)으로 미는 비즈네르, 키 위치는 모든 글자마다 넘어감
3. 소스에 소수를 그대로 적고 p2 = 2*p1 + 1 로 만든 RSA 두 쌍 (N1·FLAG1_enc 이름, 플래그를 반씩 나눔)
"""

import random
import sys
from pathlib import Path
from string import ascii_lowercase, ascii_uppercase, digits

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctfkit import brief, rsautil  # noqa: E402
from ctfkit.cli import main  # noqa: E402
from ctfkit.commands.triage import analyze, compile_pattern  # noqa: E402

PROSE = ("The history of the cipher is long and full of people who believed that their secret writing could never "
         "be read by anyone else. Many of them were wrong, and the reasons they were wrong are still worth learning "
         "today. A message that repeats a short key over a long text leaves patterns, and those patterns can be "
         "measured, counted and finally used to recover the key without ever seeing it. ")


def _start(tmp_path, files, capsys):
    chall = tmp_path / "chall"
    chall.mkdir()
    for name, data in files.items():
        (chall / name).write_bytes(data if isinstance(data, bytes) else data.encode())
    main(["start", str(chall), "--root", str(tmp_path / "ws")])   # 플래그가 없으면 1
    return capsys.readouterr().out


def test_hex_byte_caesar_in_output_text(tmp_path):
    secret = b"I wrote this down so nobody can read it. DH{byte_shift_is_not_secret}"
    enc = bytes((b + 173) % 256 for b in secret).hex()
    path = tmp_path / "output.txt"
    path.write_text(f"Here is my sentence > {enc}\n")
    report = analyze(str(path), compile_pattern(None), use_external=False)
    assert [f for f, _ in report.flags] == ["DH{byte_shift_is_not_secret}"]
    assert "173 를 뺐다" in report.evidence["DH{byte_shift_is_not_secret}"]


def test_hex_byte_xor_and_nothing_on_random_hex(tmp_path):
    secret = b"message: DH{single_byte_xor}"
    path = tmp_path / "out.txt"
    path.write_text(bytes(b ^ 0x5A for b in secret).hex())
    report = analyze(str(path), compile_pattern(None), use_external=False)
    assert report.flags and report.flags[0][0] == "DH{single_byte_xor}"
    noise = tmp_path / "noise.txt"
    noise.write_text(random.Random(4).randbytes(400).hex())
    assert not analyze(str(noise), compile_pattern(None), use_external=False).flags


VIG_SOURCE = '''import random
from string import ascii_lowercase, ascii_uppercase, digits

words = ascii_uppercase + ascii_lowercase + digits

def encrypt(pt, key):
    ct = ""
    for i in range(len(pt)):
        a = pt[i]
        ct += words[(words.index(a) + key[i % len(key)]) % len(words)] if a in words else a
    return ct

key = [random.randint(0, len(words)) for _ in range(12)]
print(encrypt(open("secret").read(), key))
'''


def _vig(text, key):
    words = ascii_uppercase + ascii_lowercase + digits
    return "".join(words[(words.index(c) + key[i % len(key)]) % 62] if c in words else c for i, c in enumerate(text))


def test_source_alphabet_vigenere(tmp_path, capsys):
    flag = "DH{" + "3f9a1c07be52d4e8" + "}"
    rng = random.Random(9)
    key = [rng.randrange(62) for _ in range(12)]
    out = _start(tmp_path, {"prob.py": VIG_SOURCE, "output.txt": _vig(PROSE * 2 + flag, key)}, capsys)
    assert f"플래그: {flag}" in out
    assert "62글자 알파벳으로 다중 시저, 키 길이 12" in out and str(key) in out


def test_source_alphabet_vigenere_reports_nothing_on_noise(tmp_path, capsys):
    rng = random.Random(2)
    words = ascii_uppercase + ascii_lowercase + digits
    noise = "".join(rng.choice(words + "  ") for _ in range(900))
    out = _start(tmp_path, {"prob.py": VIG_SOURCE, "output.txt": noise}, capsys)
    assert "플래그:" not in out and "62글자 알파벳으로 다중 시저" in out


def test_source_constants_follow_assignment_order():
    src = "from Crypto.Util.number import getPrime\np = getPrime(512)\np = 12345678901234567890123\nq = 2*p + 1\nr = getPrime(9)\n"
    found = {name: value for name, value, _ in brief.source_constants(src)}
    assert found["q"] == 2 * 12345678901234567890123 + 1 and "r" not in found
    assert [w for w, _ in brief.source_numbers(src, "a.py")] == ["a.py:3 p", "a.py:4 q"]
    assert brief.source_alphabets("import string\nA = string.ascii_letters + string.digits\n", "b.py") == \
        [("b.py:2 A", ascii_lowercase + ascii_uppercase + digits)]


def test_rsa_pairs_by_index():
    store = {"N1": 10, "e": 3, "FLAG1_enc": 5, "N2": 20, "FLAG2_enc": 7, "n_3": 30}
    assert [(i, n, e, c) for i, n, e, c in brief.rsa_pairs(store)] == [("1", 10, 3, 5), ("2", 20, 3, 7)]
    assert brief.rsa_pairs({"n": 33, "c": 4, "e": 3}) == [("", 33, 3, 4)]


def test_rsa_split_flag_with_prime_written_in_source(tmp_path, capsys):
    rng = random.Random(5)

    def prime(bits):
        while True:
            x = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
            if rsautil.is_probable_prime(x):
                return x

    while True:
        p1 = prime(256)
        if rsautil.is_probable_prime(2 * p1 + 1):
            break
    p2 = 2 * p1 + 1
    q1, q2, e = prime(256), prime(256), 65537
    flag = b"DH{half_and_half_from_source_prime}"
    m1, m2 = int.from_bytes(flag[:len(flag) // 2], "big"), int.from_bytes(flag[len(flag) // 2:], "big")
    source = (f"from Crypto.Util.number import getPrime\n\ndef safe(n):\n    p1 = getPrime(n)\n    p1 = {p1}\n"
              f"    p2 = 2*p1 + 1\n    return p1, p2\n\np1, p2 = safe(256)\nq1 = getPrime(256)\nq2 = getPrime(256)\n"
              f"e = 0x10001\nprint(f'{{N1 = }}')\n")
    output = (f"N1 = {p1 * q1}\ne = {e}\nFLAG1_enc = {pow(m1, e, p1 * q1)}\n"
              f"N2 = {p2 * q2}\ne = {e}\nFLAG2_enc = {pow(m2, e, p2 * q2)}\n")
    out = _start(tmp_path, {"prob.py": source, "output.txt": output}, capsys)
    assert f"플래그: {flag.decode()}" in out
    assert "n1: 소스의 수(files/prob.py:5 p1)와 공통 소인수: 성공" in out and "쌍 2개 모두 성공" in out
