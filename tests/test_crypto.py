"""crypto 명령 테스트 (cbc-flip, pkcs7). 모두 표준 라이브러리만으로 검증한다."""

import base64

from ctfkit.cli import main


def test_pkcs7_pad_roundtrip(capsys):
    assert main(["crypto", "pkcs7-pad", "4142", "--block", "4"]) == 0
    padded = capsys.readouterr().out.strip()
    assert padded == "41420202"                 # 4142 + 0x02 0x02
    assert main(["crypto", "pkcs7-unpad", padded, "--block", "4"]) == 0
    assert capsys.readouterr().out.strip() == "4142"


def test_pkcs7_pad_full_block(capsys):
    # 블록이 꽉 차면 한 블록 전체가 패딩으로 붙는다
    assert main(["crypto", "pkcs7-pad", "41424344", "--block", "4"]) == 0
    assert capsys.readouterr().out.strip() == "4142434404040404"


def test_pkcs7_unpad_invalid(capsys):
    assert main(["crypto", "pkcs7-unpad", "41420203", "--block", "4"]) == 2
    assert "PKCS7" in capsys.readouterr().err


def test_pkcs7_bad_hex(capsys):
    assert main(["crypto", "pkcs7-pad", "zzzz"]) == 2
    assert "hex" in capsys.readouterr().err


# --- CBC 비트플립 ---

def _blocks(n):
    return bytes(range(n))


def test_cbc_flip_changes_next_block_plaintext():
    # D(block)=block (가정) 인 토이 모델에서 P_t = C_t XOR C_{t-1}.
    # 2번째 블록 평문을 바꾸려면 1번째 블록(이전 블록)을 조작한다.
    block = 4
    c0 = bytes([10, 20, 30, 40])
    c1 = bytes([1, 2, 3, 4])
    cipher = c0 + c1
    # 토이 복호: P1 = C1 XOR C0
    p1 = bytes(a ^ b for a, b in zip(c1, c0))
    known = p1.decode("latin-1")
    desired = bytes([p1[0] ^ 0xFF, p1[1], p1[2], p1[3]]).decode("latin-1")

    code = main([
        "crypto", "cbc-flip",
        "--cipher", base64.b64encode(cipher).decode(),
        "--offset", str(block),      # 2번째 블록(평문 위치 4)
        "--known", known,
        "--desired", desired,
        "--block", str(block),
    ])
    assert code == 0


def test_cbc_flip_length_mismatch(capsys):
    cipher = base64.b64encode(bytes(32)).decode()
    code = main(["crypto", "cbc-flip", "--cipher", cipher, "--offset", "16",
                 "--known", "ab", "--desired", "abc"])
    assert code == 2
    assert "길이" in capsys.readouterr().err


def test_cbc_flip_first_block_needs_iv(capsys):
    cipher = base64.b64encode(bytes(16)).decode()
    code = main(["crypto", "cbc-flip", "--cipher", cipher, "--offset", "0",
                 "--known", "a", "--desired", "b"])
    assert code == 2
    assert "IV" in capsys.readouterr().err


def test_cbc_flip_first_block_with_iv(capsys):
    cipher = base64.b64encode(bytes(16)).decode()
    code = main(["crypto", "cbc-flip", "--cipher", cipher, "--offset", "0",
                 "--known", "a", "--desired", "b", "--iv", "00" * 16])
    assert code == 0
    out = capsys.readouterr().out
    assert "iv(hex):" in out
