"""RSA 공격에 쓰는 정수론 도구 (표준 라이브러리만).

CTF 입문~중급 RSA 문제에서 자주 나오는 약한 설정을 공략한다:
- 소인수가 가깝다 → 페르마 분해
- 작은 소인수가 있다 → 시험 나눗셈 / 폴라드 로
- 개인 지수 d 가 작다 → 비너(Wiener) 공격
- 같은 n, 서로소인 e 로 같은 평문을 두 번 암호화 → 공통 모듈러스 공격

모두 로컬 계산이며 원격 서비스 공격은 다루지 않는다(학습 목적).
"""

import math
import random

# 시험 나눗셈용 작은 소수들
_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """확장 유클리드: (g, x, y) with a*x + b*y = g = gcd(a, b)."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(a: int, m: int) -> int:
    """a 의 법 m 에 대한 곱셈 역원. 역원이 없으면 ValueError."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"역원이 없습니다 (gcd({a}, {m}) = {g})")
    return x % m


def iroot(n: int, k: int) -> tuple[int, bool]:
    """정수 k 제곱근의 내림값과 정확히 떨어지는지 여부. (큰 정수도 부동소수 오차 없이)"""
    if n < 0:
        raise ValueError("음수의 정수근은 구하지 않습니다")
    if k < 1:
        raise ValueError("k 는 1 이상이어야 합니다")
    if n == 0:
        return 0, True
    if k == 1:
        return n, True
    hi = 1 << (-(-n.bit_length() // k) + 1)
    lo = 0
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo, lo ** k == n


def is_probable_prime(n: int) -> bool:
    """밀러-라빈 소수 판정 (작은 소수 기저 + 무작위 기저 몇 개)."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    # 작은 결정적 기저 + 무작위 기저로 오류 확률을 충분히 낮춘다
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    bases += [random.randrange(2, n - 1) for _ in range(8)]
    for a in bases:
        a %= n
        if a < 2:
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def fermat_factor(n: int, max_iter: int = 1 << 22):
    """페르마 분해: n = a^2 - b^2 = (a-b)(a+b). 두 소인수가 가까울 때 매우 빠르다."""
    if n % 2 == 0:
        return 2, n // 2
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if 1 < p < n:
                return p, q
        a += 1
    return None


def pollard_rho(n: int) -> int:
    """폴라드 로(브렌트 변형): n 의 자명하지 않은 인수 하나를 찾는다."""
    if n % 2 == 0:
        return 2
    while True:
        c = random.randrange(1, n)
        f = lambda x: (x * x + c) % n
        x = y = random.randrange(2, n)
        d = 1
        while d == 1:
            x = f(x)
            y = f(f(y))
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d


def factorize(n: int) -> dict[int, int]:
    """n 을 소인수분해해 {소수: 지수} 로 돌려준다. 약한 n 만 분해된다.

    1) 작은 소수 시험 나눗셈 → 2) 가까운 소인수면 페르마 → 3) 폴라드 로 재귀.
    강한(큰 임의 소수 두 개) n 은 현실적으로 분해되지 않으며, 그때는 호출한 쪽에서
    p·q 를 직접 받아야 한다.
    """
    factors: dict[int, int] = {}

    def add(p: int):
        factors[p] = factors.get(p, 0) + 1

    for p in _SMALL_PRIMES:
        while n % p == 0:
            add(p)
            n //= p
    if n == 1:
        return factors

    stack = [n]
    while stack:
        m = stack.pop()
        if m == 1:
            continue
        if is_probable_prime(m):
            add(m)
            continue
        # 소인수가 가까운 경우를 먼저 싸게 시도
        res = fermat_factor(m, max_iter=1 << 16)
        d = res[0] if res else pollard_rho(m)
        stack.append(d)
        stack.append(m // d)
    return factors


def euler_phi(factors: dict[int, int]) -> int:
    """소인수분해로부터 오일러 피 함수 값을 계산한다."""
    phi = 1
    for p, e in factors.items():
        phi *= (p - 1) * p ** (e - 1)
    return phi


def _convergents(num: int, den: int):
    """num/den 연분수의 수렴분수 (h/k) 를 차례로 내놓는다 (h/k ≈ num/den)."""
    # h_{-2}, h_{-1} = 0, 1 / k_{-2}, k_{-1} = 1, 0 (표준 수렴분수 점화식)
    h2, h1 = 0, 1
    k2, k1 = 1, 0
    while den:
        a = num // den
        h = a * h1 + h2
        k = a * k1 + k2
        h2, h1 = h1, h
        k2, k1 = k1, k
        num, den = den, num - a * den
        yield h, k


def wiener(e: int, n: int):
    """비너 공격: 개인 지수 d 가 작을 때(대략 d < n^0.25/3) d 를 복구한다."""
    for k, d in _convergents(e, n):
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # x^2 - (n - phi + 1) x + n = 0 의 두 근이 p, q 여야 한다
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        s, exact = iroot(disc, 2)
        if exact and (b + s) % 2 == 0:
            return d
    return None


def common_modulus(e1: int, c1: int, e2: int, c2: int, n: int) -> int:
    """공통 모듈러스 공격: 같은 n, 서로소인 e1·e2 로 같은 평문을 암호화한 두 암호문에서 평문 복구."""
    g, a, b = egcd(e1, e2)
    if g != 1:
        raise ValueError(f"e1, e2 가 서로소가 아닙니다 (gcd = {g})")
    # m = c1^a * c2^b (mod n), 음수 지수는 역원으로 처리
    m1 = pow(c1, a, n) if a >= 0 else pow(modinv(c1, n), -a, n)
    m2 = pow(c2, b, n) if b >= 0 else pow(modinv(c2, n), -b, n)
    return m1 * m2 % n


def long_to_bytes(x: int) -> bytes:
    """정수를 빅엔디언 바이트열로 (복호 결과 평문을 보기 위해)."""
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")
