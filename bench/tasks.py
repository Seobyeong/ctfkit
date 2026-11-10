"""벤치마크 과제 정의.

과제마다 같은 문제를 두 가지 방법으로 푼다.
  - baseline : 파이썬 표준 라이브러리만으로 푸는 명령 (에이전트가 직접 써야 하는 코드)
  - ctfkit   : ctfkit 명령

두 방법 모두 외부 패키지를 쓰지 않는다는 같은 조건이다. baseline 은 일부러 비효율적으로
짜지 않는다: 플래그 형식(DH{...})을 알면 그것으로 걸러서 필요한 줄만 출력한다.

문제 파일은 build() 가 작업 폴더에 직접 만든다. 난수는 시드를 고정해 실행할 때마다 같다.
"""

import base64
import hashlib
import hmac
import io
import json
import random
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ctfkit import rsautil


@dataclass
class Step:
    argv: list[str]          # 실제로 실행하는 명령
    shown: str               # 에이전트가 써야 하는 글자 (작성 토큰으로 센다)


@dataclass
class Task:
    id: str
    title: str
    check: Callable[[str], bool]             # 마지막 단계의 stdout 이 정답인지
    baseline: list[Step] = field(default_factory=list)
    ctfkit: list[Step] = field(default_factory=list)


def py(code: str, *args: str) -> Step:
    """표준 라이브러리 파이썬 코드를 실행하는 단계. 한 줄이면 -c, 여러 줄이면 heredoc 으로 센다."""
    code = code.strip("\n")
    tail = "".join(f" {a}" for a in args)
    if "\n" in code:
        shown = f"python - {tail.strip()} <<'EOF'\n{code}\nEOF"
    else:
        shown = f'python -c "{code}"{tail}'
    return Step([sys.executable, "-c", code, *args], shown)


def kit(*args: str) -> Step:
    """ctfkit 명령을 실행하는 단계. 안내 출력을 끄는 -q 를 항상 붙인다."""
    return Step([sys.executable, "-m", "ctfkit", "-q", *args], "ctfkit -q " + " ".join(args))


def contains(text: str) -> Callable[[str], bool]:
    return lambda out: text in out


# ---------------------------------------------------------------- 문제 재료

ENGLISH = (
    "the history of cryptography begins thousands of years ago and until recent decades "
    "it has been the story of what might be called classical cryptography that is methods "
    "of encryption that use pen and paper or perhaps simple mechanical aids in the early "
    "twentieth century the invention of complex mechanical and electromechanical machines "
    "provided more sophisticated and efficient means of encryption"
)


def _rot13(s: str) -> str:
    return s.translate(str.maketrans(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM"))


def _caesar(s: str, k: int) -> str:
    out = []
    for c in s:
        if c.isalpha():
            base = 65 if c < "a" else 97
            out.append(chr((ord(c) - base + k) % 26 + base))
        else:
            out.append(c)
    return "".join(out)


def _vigenere(s: str, key: str) -> str:
    out, i = [], 0
    for c in s:
        if c.isalpha():
            out.append(chr((ord(c) - 97 + ord(key[i % len(key)]) - 97) % 26 + 97))
            i += 1
        else:
            out.append(c)
    return "".join(out)


def _next_prime(n: int) -> int:
    n |= 1
    while not rsautil.is_probable_prime(n):
        n += 2
    return n


def _b64url(obj) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# ---------------------------------------------------------------- baseline 코드

DEC = {
    "base64": "import base64,sys;print(base64.b64decode(sys.argv[1]).decode())",
    "base32": "import base64,sys;print(base64.b32decode(sys.argv[1]).decode())",
    "hex": "import sys;print(bytes.fromhex(sys.argv[1]).decode())",
    "rot13": "import codecs,sys;print(codecs.decode(sys.argv[1],'rot13'))",
}

CAESAR_CODE = """
import sys
s=sys.argv[1]
for k in range(26):
    t=''.join(chr((ord(c)-(65 if c<'a' else 97)-k)%26+(65 if c<'a' else 97)) if c.isalpha() else c for c in s)
    if 'DH{' in t:print(k,t)
"""

VIGENERE_CODE = """
import sys
F=[8.2,1.5,2.8,4.3,12.7,2.2,2.0,6.1,7.0,0.2,0.8,4.0,2.4,6.7,7.5,1.9,0.1,6.0,6.3,9.1,2.8,1.0,2.4,0.2,2.0,0.1]
raw=open(sys.argv[1]).read()
s=[ord(c)-97 for c in raw if c.isalpha()]
def ic(col):
    n=len(col);return sum(col.count(i)*(col.count(i)-1) for i in range(26))/(n*(n-1))
L=max(range(1,13),key=lambda l:sum(ic(s[i::l]) for i in range(l))/l-0.002*l)
key=[]
for i in range(L):
    col=s[i::L]
    def chi(k):
        return sum((col.count((j+k)%26)-len(col)*F[j]/100)**2/(len(col)*F[j]/100) for j in range(26))
    key.append(min(range(26),key=chi))
out=[];i=0
for c in raw:
    if c.isalpha():out.append(chr((ord(c)-97-key[i%L])%26+97));i+=1
    else:out.append(c)
print(''.join(chr(k+97) for k in key),''.join(out)[:60])
"""

XOR_CODE = """
import sys
d=open(sys.argv[1],'rb').read()
for k in range(256):
    t=bytes(b^k for b in d)
    if b'DH{' in t:print(k,t)
"""

FIND_FLAG_CODE = r"import re,sys;print(re.findall(rb'DH\{[ -~]+?\}',open(sys.argv[1],'rb').read()))"

JWT_DECODE_CODE = (
    "import base64,sys;"
    "print([base64.urlsafe_b64decode(x+'==') for x in sys.argv[1].split('.')[:2]])"
)

JWT_FORGE_CODE = """
import base64,json,sys
d=json.loads(base64.urlsafe_b64decode(sys.argv[1].split('.')[1]+'=='))
d['admin']=True
e=lambda o:base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).rstrip(b'=').decode()
print(e({'alg':'none','typ':'JWT'})+'.'+e(d)+'.')
"""

FERMAT_CODE = """
import math,sys
n,e,c=map(int,sys.argv[1:])
a=math.isqrt(n)+1
while math.isqrt(a*a-n)**2!=a*a-n:a+=1
b=math.isqrt(a*a-n)
m=pow(c,pow(e,-1,(a-b-1)*(a+b-1)),n)
print(m.to_bytes((m.bit_length()+7)//8,'big'))
"""

WIENER_CODE = """
import math,sys
n,e,c=map(int,sys.argv[1:])
a,b=e,n
h0,h1,k0,k1=0,1,1,0
while b:
    q=a//b;a,b=b,a-q*b
    h0,h1=h1,q*h1+h0;k0,k1=k1,q*k1+k0
    k,d=h1,k1
    if k and (e*d-1)%k==0:
        phi=(e*d-1)//k;s=n-phi+1;t=s*s-4*n
        if t>=0 and math.isqrt(t)**2==t:
            m=pow(c,d,n);print(m.to_bytes((m.bit_length()+7)//8,'big'));break
"""

ZIP_CODE = "import sys,zipfile;z=zipfile.ZipFile(sys.argv[1]);print({n:z.read(n) for n in z.namelist()})"

HASH_CODE = (
    "import hashlib,sys;"
    "print([w for w in open(sys.argv[2]).read().split() if hashlib.md5(w.encode()).hexdigest()==sys.argv[1]])"
)

CYCLIC_CODE = """
import sys
A='abcdefghijklmnopqrstuvwxyz';n=4;k=len(A);a=[0]*k*n;seq=[]
def db(t,p):
    if t>n:
        if n%p==0:seq.extend(a[1:p+1])
    else:
        a[t]=a[t-p];db(t+1,p)
        for j in range(a[t-p]+1,k):a[t]=j;db(t+1,t)
db(1,1)
s=''.join(A[i] for i in seq[:20000])
print(s.find(bytes.fromhex(sys.argv[1][2:])[::-1].decode()))
"""


# ---------------------------------------------------------------- 과제 목록

def _layered(task_id: str, title: str, flag: str, layers: list[str]) -> Task:
    """flag 를 layers 순서로 겹겹이 인코딩한 과제. baseline 은 한 번에 한 겹씩 벗긴다."""
    enc = {
        "base64": lambda s: base64.b64encode(s.encode()).decode(),
        "base32": lambda s: base64.b32encode(s.encode()).decode(),
        "hex": lambda s: s.encode().hex(),
        "rot13": _rot13,
    }
    values = [flag]
    for name in layers:
        values.append(enc[name](values[-1]))
    # 벗길 때는 바깥 겹부터. 각 단계는 직전 출력을 그대로 붙여 넣는다.
    baseline = [py(DEC[name], values[i + 1]) for i, name in reversed(list(enumerate(layers)))]
    return Task(task_id, title, contains(flag), baseline, [kit("auto", values[-1])])


def build(work: Path) -> list[Task]:
    """작업 폴더에 문제 파일을 만들고 과제 목록을 돌려준다."""
    rng = random.Random(2026)
    tasks: list[Task] = []

    # 1~3. 인코딩 한 겹 / 세 겹 / 다섯 겹
    flag = "DH{b64_is_not_encryption}"
    one = base64.b64encode(flag.encode()).decode()
    tasks.append(Task("enc-1", "Base64 한 겹", contains(flag),
                      [py(DEC["base64"], one)], [kit("codec", "decode", "b64", one)]))
    tasks.append(_layered("enc-3", "인코딩 세 겹 (hex→base64→base32)",
                          "DH{three_layers_deep}", ["hex", "base64", "base32"]))
    tasks.append(_layered("enc-5", "인코딩 다섯 겹 (rot13→base64→hex→base32→base64)",
                          "DH{five_layers}", ["rot13", "base64", "hex", "base32", "base64"]))

    # 4. 시저 (이동 칸 수 모름)
    flag = "DH{caesar_shift_found}"
    ct = _caesar(f"the flag is {flag} good luck", 7)
    tasks.append(Task("caesar", "시저 암호, 키 모름", contains(flag),
                      [py(CAESAR_CODE, f'"{ct}"')], [kit("crack", "caesar", f'"{ct}"', "-n", "1")]))
    # argv 에는 따옴표 없이 넘긴다 (shown 에만 셸 따옴표가 들어간다)
    for step in tasks[-1].baseline + tasks[-1].ctfkit:
        step.argv[:] = [a.strip('"') if a.startswith('"') else a for a in step.argv]

    # 5. 비즈네르 (키 모름)
    (work / "vig.txt").write_text(_vigenere(ENGLISH, "lemon"), encoding="ascii")
    tasks.append(Task("vigenere", "비즈네르 암호, 키 모름 (350자)", contains(ENGLISH[:40]),
                      [py(VIGENERE_CODE, "vig.txt")],
                      [kit("crack", "vigenere", "-f", "vig.txt", "-n", "1")]))

    # 6. 1바이트 XOR (키 모름)
    flag = "DH{single_byte_xor}"
    (work / "xor.bin").write_bytes(bytes(b ^ 0x5A for b in f"note: {flag} end".encode()))
    tasks.append(Task("xor", "1바이트 XOR, 키 모름", contains(flag),
                      [py(XOR_CODE, "xor.bin")], [kit("crack", "xor", "-f", "xor.bin", "-n", "1")]))

    # 7. 2MB 바이너리에서 플래그 찾기
    flag = "DH{needle_in_two_megabytes}"
    blob = bytearray(rng.randbytes(2 * 1024 * 1024))
    blob[1_234_567:1_234_567 + len(flag)] = flag.encode()
    (work / "big.bin").write_bytes(blob)
    tasks.append(Task("bigbin", "2MB 바이너리에서 플래그 찾기", contains(flag),
                      [py(FIND_FLAG_CODE, "big.bin")],
                      [kit("forensic", "strings", "big.bin", "--grep", "DH\\{")]))

    # 8. JWT: 내용 확인 후 alg:none 으로 admin 변조
    head = _b64url({"alg": "HS256", "typ": "JWT"})
    body = _b64url({"user": "guest", "admin": False})
    sig = base64.urlsafe_b64encode(
        hmac.new(b"s3cr3t", f"{head}.{body}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    token = f"{head}.{body}.{sig}"

    def forged(out: str) -> bool:
        try:
            h, p, s = out.strip().splitlines()[-1].split(".")
            dec = lambda x: json.loads(base64.urlsafe_b64decode(x + "=="))
            return dec(h)["alg"].lower() == "none" and dec(p)["admin"] is True and s == ""
        except Exception:
            return False

    tasks.append(Task("jwt", "JWT 내용 확인 후 alg:none 변조", forged,
                      [py(JWT_DECODE_CODE, token), py(JWT_FORGE_CODE, token)],
                      [kit("jwt", "decode", token),
                       kit("jwt", "forge", token, "--alg", "none", "--set", "admin=true")]))

    # 9. RSA: 소인수가 가까운 n
    flag = "DH{fermat_close_primes}"
    p = _next_prime(rng.getrandbits(128) | (1 << 127))
    q = _next_prime(p + rng.getrandbits(20))
    n, e = p * q, 65537
    c = pow(int.from_bytes(flag.encode(), "big"), e, n)
    tasks.append(Task("rsa-fermat", "RSA, 소인수가 가까운 n", contains(flag),
                      [py(FERMAT_CODE, str(n), str(e), str(c))],
                      [kit("rsa", "decrypt", "-n", str(n), "-e", str(e), "-c", str(c))]))

    # 10. RSA: 작은 개인 지수 (비너)
    flag = "DH{wiener_small_d}"
    p = _next_prime(rng.getrandbits(160) | (1 << 159))
    q = _next_prime(rng.getrandbits(160) | (1 << 159))
    n, phi = p * q, (p - 1) * (q - 1)
    d = _next_prime(rng.getrandbits(64) | (1 << 63))
    while phi % d == 0:
        d = _next_prime(d + 2)
    e = pow(d, -1, phi)
    c = pow(int.from_bytes(flag.encode(), "big"), e, n)
    tasks.append(Task("rsa-wiener", "RSA, 작은 개인 지수 (비너)", contains(flag),
                      [py(WIENER_CODE, str(n), str(e), str(c))],
                      [kit("rsa", "wiener", "-n", str(n), "-e", str(e), "-c", str(c))]))

    # 11. PNG 뒤에 붙은 ZIP 안의 플래그 (압축돼 있어 문자열 검색으로는 안 보인다)
    flag = "DH{zip_after_png}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("flag.txt", ("padding line\n" * 40) + flag + "\n")
    (work / "pic.png").write_bytes(b"\x89PNG\r\n\x1a\n" + rng.randbytes(4096) + buf.getvalue())
    tasks.append(Task("carve-zip", "PNG 뒤에 붙은 ZIP 안의 플래그", contains(flag),
                      [py(ZIP_CODE, "pic.png")],
                      [kit("forensic", "carve", "pic.png", "--dump", "out.zip"),
                       py(ZIP_CODE, "out.zip")]))

    # 12. 해시 사전 공격 (5000 단어)
    words = ["".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(8)) for _ in range(5000)]
    secret = words[4321]
    (work / "words.txt").write_text("\n".join(words) + "\n", encoding="ascii")
    digest = hashlib.md5(secret.encode()).hexdigest()
    tasks.append(Task("hash", "MD5 사전 공격 (5000 단어)", contains(secret),
                      [py(HASH_CODE, digest, "words.txt")],
                      [kit("hash", "crack", digest, "-w", "words.txt")]))

    # 13. cyclic 패턴 오프셋 역산
    tasks.append(Task("cyclic", "cyclic 패턴 오프셋 역산", lambda out: out.strip().splitlines()[-1:] == ["20"],
                      [py(CYCLIC_CODE, "0x61616166")],
                      [kit("pwn", "cyclic", "-l", "0x61616166")]))

    return tasks
