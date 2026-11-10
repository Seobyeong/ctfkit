"""v0.18 rsa 테스트: 약한 RSA 공격 (소인수분해·복호·비너·공통 모듈러스).

모두 로컬 계산이며, 작은/약한 파라미터로 공격이 정확히 동작하는지 확인한다.
"""

import pytest

from ctfkit import rsautil as R
from ctfkit.cli import main

# 검증된 고정 소수들 (테스트 속도를 위해 작게)
P_CLOSE = 0x1000000000000000D        # 2^64 근처, 서로 가깝다 → 페르마
Q_CLOSE = 0x100000000000003ED
P128 = 0x80000000000000000000000000003053   # 비너용 128비트 소수
Q128 = 0x8000000000000000000000000001869F
SMALL = 100003                        # 작은 소수


# --- 정수론 유틸 ---

def test_modinv_and_egcd():
    assert R.modinv(17, 3120) == 2753
    g, x, y = R.egcd(240, 46)
    assert g == 2 and 240 * x + 46 * y == 2


def test_iroot_exact_and_floor():
    assert R.iroot(10 ** 100, 2) == (10 ** 50, True)
    root, exact = R.iroot(10 ** 100 + 1, 2)
    assert root == 10 ** 50 and exact is False


def test_is_probable_prime():
    assert R.is_probable_prime(P_CLOSE)
    assert not R.is_probable_prime(P_CLOSE * Q_CLOSE)


# --- 소인수분해 ---

def test_factor_close_primes_fermat():
    n = P_CLOSE * Q_CLOSE
    assert set(R.factorize(n)) == {P_CLOSE, Q_CLOSE}


def test_factor_small_times_large():
    n = SMALL * P_CLOSE
    assert set(R.factorize(n)) == {SMALL, P_CLOSE}


# --- 복호 ---

def test_decrypt_roundtrip():
    n = P_CLOSE * Q_CLOSE
    e = 65537
    m = int.from_bytes(b"flag{rsa}", "big")
    c = pow(m, e, n)
    factors = R.factorize(n)
    d = R.modinv(e, R.euler_phi(factors))
    assert R.long_to_bytes(pow(c, d, n)) == b"flag{rsa}"


# --- 공통 모듈러스 ---

def test_common_modulus_recovers_plaintext():
    n = P128 * Q128
    m = int.from_bytes(b"shared secret", "big")
    e1, e2 = 3, 65537
    c1, c2 = pow(m, e1, n), pow(m, e2, n)
    assert R.common_modulus(e1, c1, e2, c2, n) == m


def test_common_modulus_requires_coprime_e():
    n = P128 * Q128
    with pytest.raises(ValueError):
        R.common_modulus(4, 1, 6, 1, n)   # gcd(4,6)=2


# --- 비너 (작은 d) ---

def test_wiener_recovers_small_d():
    n = P128 * Q128
    phi = (P128 - 1) * (Q128 - 1)
    d = 1234577                           # n^0.25 (~2^64) 보다 훨씬 작다
    e = R.modinv(d, phi)
    assert R.wiener(e, n) == d


def test_wiener_fails_for_normal_d():
    n = P128 * Q128
    phi = (P128 - 1) * (Q128 - 1)
    e = 65537
    assert R.wiener(e, n) is None        # 일반 d 는 복구되지 않는다


# --- CLI ---

def test_cli_factor(capsys):
    assert main(["rsa", "factor", str(P_CLOSE * Q_CLOSE)]) == 0
    out = capsys.readouterr().out
    assert str(P_CLOSE) in out and str(Q_CLOSE) in out


def test_cli_decrypt(capsys):
    n = P_CLOSE * Q_CLOSE
    e = 65537
    c = pow(int.from_bytes(b"hi!", "big"), e, n)
    rc = main(["rsa", "decrypt", "-n", str(n), "-e", str(e), "-c", str(c)])
    assert rc == 0
    assert "hi!" in capsys.readouterr().out


def test_cli_decrypt_with_given_pq(capsys):
    n = P128 * Q128
    e = 65537
    m = int.from_bytes(b"given pq", "big")
    c = pow(m, e, n)
    rc = main(["rsa", "decrypt", "-n", str(n), "-e", str(e), "-c", str(c),
               "-p", str(P128), "-q", str(Q128)])
    assert rc == 0
    assert "given pq" in capsys.readouterr().out


def test_cli_common_modulus(capsys):
    n = P128 * Q128
    m = int.from_bytes(b"cm", "big")
    c1, c2 = pow(m, 3, n), pow(m, 65537, n)
    rc = main(["rsa", "common-modulus", "-n", str(n),
               "--e1", "3", "--c1", str(c1), "--e2", "65537", "--c2", str(c2)])
    assert rc == 0
    assert "cm" in capsys.readouterr().out
