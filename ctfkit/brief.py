"""AI 에이전트가 읽을 요약: 소스의 사실, 성립하지 않는 공격(소거), 값 파일, 줄인 소스.

에이전트가 소스를 받은 문제에서 토큰을 가장 많이 쓰는 곳은 **틀린 공격을 시도하는 왕복**이다. 공격 스크립트를 쓰고,
실행하고, 결과를 읽고, 버린다. 여기서는 그 왕복을 두 가지로 줄인다.

  1. 소거: 공격마다 전제 조건이 있다 (페르마 = 두 소수가 가깝다, 패딩 오라클 = 서버가 내 입력을 복호화한다).
     소스를 ast 로 읽어 전제 조건이 코드에 **사실로** 없을 때만 "제외" 라고 한다. 확실하지 않으면 아무 말도 하지 않는다.
     틀린 제외는 틀린 제안보다 나쁘다 (정답 경로를 아예 안 보게 된다).
  2. 시도: 값(n, e, c)이 파일에 있으면 몇 초 안에 끝나는 공격을 직접 돌려 보고, 몇 번 시도했는지와 함께 적는다.

그리고 읽는 양을 줄인다.

  3. 값 파일: 큰 정수를 에이전트가 스크립트에 옮겨 적지 않도록 values.json 으로 모은다.
  4. 소스 압축: 의미가 없는 부분(표준 S-box, 큰 데이터 상수, 배너 출력, 어디서도 부르지 않는 함수)만 줄이고,
     줄인 자리에는 원본 줄 번호를 남긴다. 로직은 한 줄도 요약하지 않는다. 버그는 평범해 보이는 코드에 숨어 있다.

공격 방법을 추측하지 않는다는 source.py 의 원칙은 그대로다. 여기서 "후보" 는 전제 조건이 코드에 보인다는 뜻일 뿐이다.
"""

import ast
import json
import math
import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------- 결과 모양

EXCLUDED = "제외"
CANDIDATE = "후보"


@dataclass
class Verdict:
    attack: str            # 공격 이름
    status: str            # EXCLUDED | CANDIDATE
    reason: str            # 근거 (코드에 보이는 사실)
    lines: tuple = ()      # 근거가 있는 원본 줄 번호
    tip: str = ""          # 후보일 때 쓸 ctfkit 명령 (앞에 "ctfkit " 없이)

    def where(self, name: str) -> str:
        return ", ".join(f"{name}:{n}" for n in sorted(set(self.lines)))


@dataclass
class SourceBrief:
    name: str
    facts: list = field(default_factory=list)      # [(줄 번호, 사실)]
    verdicts: list = field(default_factory=list)
    e: int | None = None                            # RSA 공개 지수를 소스에서 확정할 수 있었으면 그 값

    @property
    def excluded(self) -> list:
        return [v for v in self.verdicts if v.status == EXCLUDED]

    @property
    def candidates(self) -> list:
        return [v for v in self.verdicts if v.status == CANDIDATE]

    def fact(self, line: int, text: str) -> None:
        if (line, text) not in self.facts:
            self.facts.append((line, text))

    def lines(self) -> list[str]:
        """사람·에이전트가 읽을 몇 줄 (사실 → 제외 → 후보)."""
        out = [f"사실: {self.name}:{n} {text}" for n, text in sorted(self.facts)]
        for v in self.excluded:
            out.append(f"제외: {v.attack} - {v.reason}" + (f" ({v.where(self.name)})" if v.lines else ""))
        for v in self.candidates:
            out.append(f"후보: {v.attack} - {v.reason}" + (f" ({v.where(self.name)})" if v.lines else "")
                       + (f" → ctfkit {v.tip}" if v.tip else ""))
        return out


# ---------------------------------------------------------------- ast 도우미

_PRIME_GEN = {"getPrime", "getStrongPrime", "generate_prime", "random_prime", "randprime", "get_prime"}
_NEXT_PRIME = {"next_prime", "nextprime", "next_probable_prime", "NextPrime", "next_probable_prime"}
_PRIME_TEST = {"isPrime", "is_prime", "isprime", "is_probable_prime", "is_pseudoprime"}
_RANDOM_BYTES = {"urandom", "get_random_bytes", "token_bytes"}
_CIPHERS = {"AES", "DES", "DES3", "Blowfish", "ARC4", "ChaCha20", "Salsa20", "CAST", "ARC2"}
# 이름을 글자로 찾아 부를 수 있는 것들. 보이면 "부르지 않는 함수" 를 줄이지 않는다 (pickle 은 __reduce__ 로 부른다)
_DYNAMIC = {"getattr", "globals", "locals", "eval", "exec", "vars", "__import__", "loads", "load", "compile"}
_INPUT_CALLS = {"input", "recv", "recvline", "recvuntil", "readline", "get_json"}


def _name(node) -> str | None:
    """호출·속성의 마지막 이름 (os.urandom → urandom, getPrime → getPrime)."""
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _const_int(node) -> int | None:
    """상수 정수 식의 값. 0x10001, 2**16 + 1, 1 << 16 처럼 상수끼리의 계산까지만 본다."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.BinOp):
        a, b = _const_int(node.left), _const_int(node.right)
        if a is None or b is None:
            return None
        ops = {ast.Add: lambda: a + b, ast.Sub: lambda: a - b, ast.Mult: lambda: a * b,
               ast.Pow: lambda: a ** b if 0 <= b <= 4096 and abs(a) < 1 << 64 else None,
               ast.LShift: lambda: a << b if 0 <= b <= 4096 else None}
        fn = ops.get(type(node.op))
        return fn() if fn else None
    return None


class _Code:
    """소스 하나에서 반복해 쓰는 정보를 한 번에 모은다."""

    def __init__(self, tree: ast.AST):
        self.tree = tree
        self.calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
        self.assigns: dict[str, list] = {}   # 이름 → [(값 노드 또는 None, 줄)]
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    self._target(target, node.value, node.lineno)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                self._target(node.target, node.value, node.lineno)
            elif isinstance(node, (ast.AugAssign, ast.NamedExpr)):
                self._target(node.target, None, node.lineno)
            elif isinstance(node, (ast.For, ast.comprehension)):
                self._target(node.target, None, getattr(node, "lineno", 0))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                # 함수 인자는 호출하는 쪽이 값을 정한다
                for arg in node.args.args + node.args.kwonlyargs:
                    self.assigns.setdefault(arg.arg, []).append((None, getattr(node, "lineno", 0)))
        self.imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.imports |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                self.imports.add(node.module.split(".")[0])

    def _target(self, target, value, line):
        if isinstance(target, (ast.Tuple, ast.List)):
            same = isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(target.elts)
            for i, elt in enumerate(target.elts):
                self._target(elt, value.elts[i] if same else None, line)
            return
        key = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else None
        if key:
            self.assigns.setdefault(key, []).append((value, line))

    def single(self, name: str):
        """name 에 값을 꼭 한 번만 넣었으면 (값 노드, 줄). 두 번 이상이거나 알 수 없는 값이면 None."""
        found = self.assigns.get(name, [])
        if len(found) == 1 and found[0][0] is not None:
            return found[0]
        return None

    def called(self, *names: str) -> list:
        return [c for c in self.calls if _name(c) in names]

    def has_input(self) -> list:
        """입력을 받는 곳의 줄 번호. 웹(request.*)과 표준 입력·소켓을 모두 본다."""
        lines = [c.lineno for c in self.calls if _name(c) in _INPUT_CALLS]
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and \
                    (node.value.id == "request" or (node.value.id == "sys" and node.attr == "stdin")):
                lines.append(node.lineno)
        return sorted(set(lines))


# ---------------------------------------------------------------- 소거 규칙

def analyze_source(text: str, name: str = "source.py") -> SourceBrief | None:
    """파이썬 소스의 사실과 공격별 판정. 파이썬이 아니거나 문법이 깨졌으면 None (판단하지 않는다)."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    code = _Code(tree)
    out = SourceBrief(name)
    _rsa_rules(code, out)
    _cipher_rules(code, out)
    _random_rules(code, out)
    _remote_rule(code, out, name)
    return out


def _rsa_rules(code: _Code, out: SourceBrief) -> None:
    gens = code.called(*_PRIME_GEN)
    pows = [c for c in code.called("pow") if len(c.args) == 3]
    if not gens and not ({"bytes_to_long", "long_to_bytes"} & {_name(c) for c in code.calls} and pows):
        return

    # e: 한 번만 넣은 상수, 또는 이름 없이 pow(m, 상수, n) 로만 쓴 경우
    e, e_line = None, None
    for key in ("e", "E"):
        found = code.single(key)
        if found and _const_int(found[0]) is not None:
            e, e_line = _const_int(found[0]), found[1]
        if key in code.assigns:
            break
    if e is None and "e" not in code.assigns and "E" not in code.assigns and pows:
        consts = {_const_int(c.args[1]) for c in pows}
        if len(consts) == 1 and None not in consts:
            e, e_line = consts.pop(), pows[0].lineno
    if e is not None:
        out.fact(e_line, f"e = {e}")
        out.e = e

    bits = [_const_int(g.args[0]) if g.args else None for g in gens]
    for g, b in zip(gens, bits):
        if b is not None:
            out.fact(g.lineno, f"{_name(g)}({b})")
    derived = code.called(*_NEXT_PRIME)
    custom = code.called(*_PRIME_TEST)

    # 작은 e: m >= 2 이면 m^e >= 2^e. e 가 n 의 비트 수보다 크면 m^e 는 반드시 n 을 넘어 나머지 연산이 걸린다
    if e is not None and e >= 65537:
        out.verdicts.append(Verdict("작은 e (e제곱근)", EXCLUDED,
                                    f"e={e}: m≥2 면 m^e ≥ 2^{e} 로 n 보다 크다", (e_line,)))
    elif e is not None and 1 < e <= 17:
        out.verdicts.append(Verdict("작은 e (e제곱근)", CANDIDATE, f"e={e}", (e_line,), "template rsa -n N -e E -c C"))

    # 비너: d < n^0.25/3 이어야 한다. d = e^-1 mod φ 이면 d·e = kφ + 1 (k ≥ 1) 이므로 d > φ/e. e 가 작으면 d 는 크다
    small_d = [v for k in ("d", "D") for v, _ in code.assigns.get(k, []) if v is not None and _name(v) in _PRIME_GEN]
    if small_d:
        out.verdicts.append(Verdict("비너 (작은 d)", CANDIDATE, "d 를 소수로 먼저 정함",
                                    tuple(v.lineno for v in small_d), "rsa wiener -n N -e E -c C"))
    elif e is not None and 1 < e < 1 << 64:
        out.verdicts.append(Verdict("비너 (작은 d)", EXCLUDED, f"e={e} 가 작아 d > φ/e (비너는 d < n^0.25 필요)",
                                    (e_line,)))

    # 페르마: 두 소수가 가까워야 한다. 소수를 각각 따로 뽑고, 한 소수에서 다른 소수를 만드는 코드가 없을 때만 제외
    shifted = _shifted_primes(code, gens)
    if derived or shifted:
        lines = tuple(c.lineno for c in derived) + tuple(shifted)
        why = f"{_name(derived[0])}() 로 소수를 이어서 만듦" if derived else "한 소수에 값을 더해 다른 수를 만듦"
        out.verdicts.append(Verdict("페르마 (가까운 소수)", CANDIDATE, why, lines, "rsa factor N"))
    elif not custom and (len(gens) >= 2 or (gens and _in_loop(code.tree, gens[0]))):
        out.verdicts.append(Verdict("페르마 (가까운 소수)", EXCLUDED, "소수를 각각 따로 뽑음",
                                    tuple(g.lineno for g in gens)))

    # 작은 소인수(시험 나눗셈): 모든 소수가 64비트 이상이면 성립하지 않는다
    if gens and all(b is not None and b >= 64 for b in bits) and not custom:
        out.verdicts.append(Verdict("작은 소인수", EXCLUDED, f"소수 {min(bits)}비트 이상",
                                    tuple(g.lineno for g in gens)))


def _shifted_primes(code: _Code, gens) -> list[int]:
    """소수 변수에 값을 더하거나 비트를 바꿔 새 값을 만드는 줄 (q = p + 2 등). p - 1 은 φ 계산이라 뺀다."""
    primes = {key for key, found in code.assigns.items()
              if any(value is not None and any(value is g for g in gens) for value, _ in found)}
    lines = []
    for node in ast.walk(code.tree):
        if not isinstance(node, ast.BinOp) or not isinstance(node.op, (ast.Add, ast.Sub, ast.BitXor, ast.BitOr)):
            continue
        sides = (node.left, node.right)
        if not any(isinstance(s, ast.Name) and s.id in primes for s in sides):
            continue
        other = node.right if isinstance(node.left, ast.Name) and node.left.id in primes else node.left
        if isinstance(node.op, (ast.Add, ast.Sub)) and _const_int(other) == 1:
            continue   # p - 1, p + 1
        lines.append(node.lineno)
    return sorted(set(lines))


def _in_loop(tree, target) -> bool:
    """target 호출이 반복문이나 컴프리헨션 안에 있는가."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.While, ast.ListComp, ast.GeneratorExp, ast.SetComp, ast.DictComp)):
            if any(child is target for child in ast.walk(node)):
                return True
    return False


def _cipher_rules(code: _Code, out: SourceBrief) -> None:
    news = [c for c in code.calls if isinstance(c.func, ast.Attribute) and c.func.attr == "new"
            and isinstance(c.func.value, ast.Name) and c.func.value.id in _CIPHERS]
    if not news:
        return
    modes, known = set(), True
    for c in news:
        mode_args = [a for a in list(c.args[1:2]) + [k.value for k in c.keywords if k.arg == "mode"]]
        if c.func.value.id in ("ARC4", "ChaCha20", "Salsa20"):
            modes.add("STREAM")
            continue
        if not mode_args or not (isinstance(mode_args[0], ast.Attribute) and mode_args[0].attr.startswith("MODE_")):
            known = False   # 모드를 변수로 넘기면 어떤 모드인지 모른다
            continue
        modes.add(mode_args[0].attr[5:])
    if known and modes:
        out.fact(news[0].lineno, f"{'·'.join(sorted({c.func.value.id for c in news}))} 모드 {'·'.join(sorted(modes))}")
    decrypts = [c.lineno for c in code.calls if isinstance(c.func, ast.Attribute) and c.func.attr == "decrypt"]
    encrypts = [c.lineno for c in code.calls if isinstance(c.func, ast.Attribute) and c.func.attr == "encrypt"]
    inputs = code.has_input()
    where = tuple(c.lineno for c in news)

    # 서버가 내 암호문을 복호화하지 않으면 패딩 오라클·비트 플립은 성립하지 않는다
    if not decrypts:
        reason = "소스에 .decrypt() 호출이 없음"
        out.verdicts.append(Verdict("패딩 오라클", EXCLUDED, reason, where))
        out.verdicts.append(Verdict("CBC 비트 플립", EXCLUDED, reason, where))
    elif not inputs:
        reason = "입력을 받는 곳이 없음 (서버에 암호문을 보낼 수 없다)"
        out.verdicts.append(Verdict("패딩 오라클", EXCLUDED, reason, tuple(decrypts)))
        out.verdicts.append(Verdict("CBC 비트 플립", EXCLUDED, reason, tuple(decrypts)))
    elif known and "CBC" not in modes:
        out.verdicts.append(Verdict("CBC 비트 플립", EXCLUDED, f"CBC 를 쓰지 않음 (모드 {'·'.join(sorted(modes))})", where))
        if "ECB" not in modes:
            out.verdicts.append(Verdict("패딩 오라클", EXCLUDED, "블록 패딩을 쓰는 모드(CBC·ECB)가 아님", where))
    elif known and "CBC" in modes:
        out.verdicts.append(Verdict("CBC 비트 플립", CANDIDATE, "CBC 복호화 + 입력",
                                    tuple(decrypts[:1] + inputs[:1]),
                                    "crypto cbc-flip --cipher B64 --offset N --known A --desired B"))
        unpads = [c.lineno for c in code.called("unpad")]
        if unpads:
            out.verdicts.append(Verdict("패딩 오라클", CANDIDATE, "CBC 복호화 + unpad + 입력 (패딩 오류가 응답으로 드러나는지 확인)",
                                        tuple(decrypts[:1] + unpads[:1] + inputs[:1])))

    # ECB 한 바이트씩 (byte-at-a-time): ECB 로 내 입력과 비밀을 함께 암호화해 돌려줘야 한다
    if known and "ECB" not in modes:
        out.verdicts.append(Verdict("ECB 한 바이트씩 복구", EXCLUDED, "ECB 를 쓰지 않음", where))
    elif not encrypts or not inputs:
        out.verdicts.append(Verdict("ECB 한 바이트씩 복구", EXCLUDED,
                                    "암호화 오라클 없음 (" + ("encrypt 호출 없음" if not encrypts else "입력 없음") + ")", where))
    elif known and "ECB" in modes:
        out.verdicts.append(Verdict("ECB 한 바이트씩 복구", CANDIDATE, "ECB 암호화 + 입력", tuple(encrypts[:1] + inputs[:1])))

    # 키 전수 조사: 키가 운영체제 난수 8바이트 이상이면 2^64 이상
    keys = {c.args[0].id for c in news if c.args and isinstance(c.args[0], ast.Name)}
    keys |= {k.value.id for c in news for k in c.keywords if k.arg == "key" and isinstance(k.value, ast.Name)}
    for key in sorted(keys):
        found = code.single(key)
        if not found or _name(found[0]) not in _RANDOM_BYTES or not isinstance(found[0], ast.Call):
            continue
        size = _const_int(found[0].args[0]) if found[0].args else None
        if size is not None and size >= 8:
            out.fact(found[1], f"{key} = {_name(found[0])}({size})")
            out.verdicts.append(Verdict("키 전수 조사", EXCLUDED, f"{key} 가 운영체제 난수 {size}바이트", (found[1],)))
        elif size is not None and size <= 3:
            out.verdicts.append(Verdict("키 전수 조사", CANDIDATE, f"{key} 가 {size}바이트뿐", (found[1],)))


def _random_rules(code: _Code, out: SourceBrief) -> None:
    secure = code.called(*_RANDOM_BYTES, "randbelow", "token_hex")
    uses_random = "random" in code.imports and any(
        isinstance(c.func, ast.Attribute) and isinstance(c.func.value, ast.Name) and c.func.value.id == "random"
        for c in code.calls)
    from_random = "random" in code.imports and any(
        isinstance(n, ast.ImportFrom) and n.module == "random" for n in ast.walk(code.tree))
    if uses_random or from_random:
        seeds = [c for c in code.calls if _name(c) == "seed"]
        timed = [c for c in seeds if any(_name(x) in ("time", "time_ns", "now") for x in ast.walk(c))]
        if timed:
            out.verdicts.append(Verdict("난수 예측", CANDIDATE, "시드가 현재 시각", tuple(c.lineno for c in timed)))
        else:
            lines = tuple(sorted({c.lineno for c in code.calls if isinstance(c.func, ast.Attribute)
                                  and isinstance(c.func.value, ast.Name) and c.func.value.id == "random"}))[:3]
            out.verdicts.append(Verdict("난수 예측", CANDIDATE, "random(MT19937) 사용: 32비트 출력 624개면 상태 복구",
                                        lines))
    elif secure and "random" not in code.imports and "numpy" not in code.imports:
        out.verdicts.append(Verdict("난수 예측", EXCLUDED, "운영체제 난수만 씀 (random 모듈 없음)",
                                    tuple(c.lineno for c in secure[:3])))


def _remote_rule(code: _Code, out: SourceBrief, name: str) -> None:
    inputs = code.has_input()
    web = {"flask", "fastapi", "django", "bottle", "aiohttp", "tornado"} & code.imports
    if web:
        return   # 웹 문제는 template web 이 맡는다
    if inputs:
        out.fact(inputs[0], "입력을 받음")
        out.verdicts.append(Verdict("nc 접속 클라이언트", CANDIDATE, "입력을 받음", tuple(inputs[:1]),
                                    f"template remote {name} --host HOST --port PORT"))
    elif code.called("print", "write"):
        out.verdicts.append(Verdict("nc 접속 클라이언트", EXCLUDED,
                                    "입력을 받는 곳이 없음: 값은 함께 준 출력 파일에 있다"))


# ---------------------------------------------------------------- 값 파일

_VALUE = re.compile(r"(?<![\w.])([A-Za-z_]\w{0,15})\s*[=:]\s*(-?(?:0x[0-9a-fA-F]+|\d+))(?![\w.])")
MAX_VALUES = 64


def extract_values(text: str) -> list[tuple[str, int, int]]:
    """글자 파일에서 '이름 = 정수' / '이름: 정수' 를 [(이름, 값, 줄)] 로. 같은 이름은 처음 것만."""
    out, seen = [], set()
    for lineno, line in enumerate(text.splitlines(), 1):
        for m in _VALUE.finditer(line):
            name = m.group(1)
            if name in seen:
                continue
            raw = m.group(2)
            try:
                value = int(raw, 16) if raw.lower().lstrip("-").startswith("0x") else int(raw)
            except ValueError:
                continue
            seen.add(name)
            out.append((name, value, lineno))
            if len(out) >= MAX_VALUES:
                return out
    return out


def merge_values(store: dict, origins: dict, found, where: str) -> list[str]:
    """store 에 값을 더한다. 이름이 겹치고 값이 다르면 n_2 처럼 번호를 붙인다. 더한 이름 목록을 돌려준다."""
    added = []
    for name, value, line in found:
        key, k = name, 1
        while key in store and store[key] != value:
            k += 1
            key = f"{name}_{k}"
        if key in store:
            continue
        store[key] = value
        origins[key] = f"{where}:{line}"
        added.append(key)
    return added


def describe_value(name: str, value: int) -> str:
    return f"{name}({value.bit_length()}비트)" if value.bit_length() > 64 else f"{name}={value}"


def write_values(path: str, store: dict, origins: dict) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(dict(store, _from=origins), f, indent=1)


# ---------------------------------------------------------------- 값으로 직접 시도 (RSA)

FERMAT_STEPS = 1 << 16
TRIAL_LIMIT = 1 << 16


def _small_primes(limit: int) -> list[int]:
    sieve = bytearray([1]) * limit
    sieve[0:2] = b"\x00\x00"
    for i in range(2, math.isqrt(limit) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(range(i * i, limit, i)))
    return [i for i in range(limit) if sieve[i]]


def pick(store: dict, *names: str) -> str | None:
    """store 에서 names 중 처음 맞는 키 (대소문자 무시). 값이 정수인 것만."""
    for name in names:
        for key, value in store.items():
            if key.lower() == name and isinstance(value, int) and not isinstance(value, bool):
                return key
    return None


def _lookup(store: dict, *names: str):
    key = pick(store, *names)
    return None if key is None else store[key]


def try_rsa(store: dict, e_hint: int | None = None) -> tuple[list[str], bytes | None]:
    """values 에 n·c (그리고 e) 가 있으면 가벼운 공격을 돌린다. ([시도 기록], 평문 또는 None).

    시도 기록은 "무엇을 어디까지 해 봤는가" 다. 실패했다고 그 공격이 불가능하다는 뜻은 아니므로 "제외" 와 따로 적는다.
    """
    from ctfkit import rsautil

    n = _lookup(store, "n", "modulus", "n1")
    c = _lookup(store, "c", "ct", "cipher", "ciphertext", "enc", "c1")
    e = _lookup(store, "e", "exponent", "e1")
    if e is None:
        e = e_hint
    if n is None or c is None or e is None or n < 4 or e < 1:
        return [], None
    tried = []

    def checked(p: int) -> str:
        q = n // p
        return f"p·q = n 확인, p {p.bit_length()}비트·q {q.bit_length()}비트"

    def plain(p: int):
        q = n // p
        if p * q != n:
            return None
        phi = (p - 1) * (q - 1) if p != q else p * (p - 1)
        if math.gcd(e, phi) != 1:
            return None
        return rsautil.long_to_bytes(pow(c, pow(e, -1, phi), n))

    if e <= 17:
        for k in range(1001 if e <= 5 else 1):
            m, exact = rsautil.iroot(c + k * n, e)
            if exact:
                tried.append(f"작은 e: 성공 (m^{e} = c + {k}·n 확인)")
                return tried, rsautil.long_to_bytes(m)
        tried.append(f"작은 e: c + k·n (k ≤ {1000 if e <= 5 else 0}) 의 {e}제곱근 - 실패")

    for p in _small_primes(TRIAL_LIMIT):
        if n % p == 0 and p < n:
            tried.append(f"작은 소인수: 성공 (p={p}, {checked(p)})")
            return tried, plain(p)
    tried.append(f"작은 소인수 (< {TRIAL_LIMIT}) - 실패")

    found = rsautil.fermat_factor(n, FERMAT_STEPS)
    if found:
        tried.append(f"페르마: 성공 ({checked(found[0])})")
        return tried, plain(found[0])
    tried.append(f"페르마 {FERMAT_STEPS}회 - 실패")

    d = rsautil.wiener(e, n)
    if d:
        tried.append(f"비너: 성공 (d {d.bit_length()}비트, (e·d - 1) 이 k·φ 꼴이고 p, q 가 정수근)")
        return tried, rsautil.long_to_bytes(pow(c, d, n))
    tried.append("비너 - 실패")

    others = [v for k, v in store.items() if re.fullmatch(r"n_?\d+|n\d*_\d+", k.lower()) and v != n and v > 3]
    for other in others:
        g = math.gcd(n, other)
        if 1 < g < n:
            tried.append(f"다른 n 과 공통 소인수: 성공 ({checked(g)})")
            return tried, plain(g)
    if others:
        tried.append(f"다른 n {len(others)}개와 공통 소인수 - 실패")
    tried.append("factordb 조회는 하지 않음 (네트워크)")
    return tried, None


# ---------------------------------------------------------------- 소스 압축

def _aes_sbox() -> list[int]:
    """AES S-box 를 정의대로 계산한다 (GF(2^8) 역원 + 아핀 변환). 표를 소스에 다시 적지 않는다."""
    def mul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
            b >>= 1
        return r

    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if mul(a, b) == 1:
                inv[a] = b
                break
    box = []
    for x in inv:
        y = x
        for shift in range(1, 5):
            y ^= ((x << shift) | (x >> (8 - shift))) & 0xFF
        box.append(y ^ 0x63)
    return box


_KNOWN_TABLES = None


def _known_tables() -> dict:
    global _KNOWN_TABLES
    if _KNOWN_TABLES is None:
        box = _aes_sbox()
        inv = [0] * 256
        for i, v in enumerate(box):
            inv[v] = i
        _KNOWN_TABLES = {tuple(box): "AES 표준 S-box", tuple(inv): "AES 표준 역 S-box"}
    return _KNOWN_TABLES


MIN_TABLE = 32          # 이보다 원소가 적은 리스트는 그대로 둔다
MIN_STRING = 200        # 이보다 짧은 글자 상수는 그대로 둔다
MIN_PRINTS = 3          # 글자만 출력하는 print 가 이만큼 이어지면 줄인다


@dataclass
class Compacted:
    text: str
    original_lines: int
    elided: list = field(default_factory=list)   # [(시작 줄, 끝 줄, 설명)]

    @property
    def kept_lines(self) -> int:
        return self.text.count("\n")


def _flat_consts(node) -> list | None:
    """리스트·튜플·집합(중첩 포함)의 원소가 모두 상수면 평평한 목록, 아니면 None."""
    out = []
    for elt in getattr(node, "elts", []):
        if isinstance(elt, ast.Constant):
            out.append(elt.value)
        elif isinstance(elt, (ast.List, ast.Tuple, ast.Set)):
            inner = _flat_consts(elt)
            if inner is None:
                return None
            out += inner
        elif isinstance(elt, ast.UnaryOp) and isinstance(elt.operand, ast.Constant):
            out.append(elt.operand.value)
        else:
            return None
    return out


def _string_kind(s) -> str | None:
    """줄여도 되는 긴 글자 상수의 종류. 사람이 읽는 문장(힌트일 수 있다)이면 None."""
    text = s.decode("latin-1") if isinstance(s, bytes) else s
    compact = re.sub(r"\s", "", text)
    if not compact:
        return None
    if re.fullmatch(r"[0-9a-fA-F]+", compact):
        return "hex"
    if re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact) and " " not in text.strip():
        return "base64 모양"
    alnum = sum(ch.isalnum() for ch in text) / len(text)
    if alnum < 0.35:
        return "그림 글자(배너)"
    return None


def _table_desc(values: list) -> str | None:
    """줄일 표의 설명. 줄이면 안 되는 표(표준과 다른 0~255 순열 = 직접 만든 S-box)는 None."""
    if len(values) < MIN_TABLE:
        return None
    if all(isinstance(v, int) and not isinstance(v, bool) for v in values):
        known = _known_tables().get(tuple(values))
        if known:
            return f"정수 {len(values)}개: {known} 와 같음"
        if sorted(values) == list(range(256)):
            return None   # 표준과 다른 S-box. 취약점이 여기 있을 수 있다
        return f"정수 {len(values)}개, 처음 {', '.join(map(str, values[:3]))}"
    if all(isinstance(v, (str, bytes)) for v in values):
        return f"글자 {len(values)}개"
    return f"상수 {len(values)}개"


def _col(line: str, byte_col: int) -> int:
    """ast 의 열 번호(UTF-8 바이트)를 글자 위치로."""
    return len(line.encode("utf-8")[:byte_col].decode("utf-8", "ignore"))


def compact(text: str, name: str = "source") -> Compacted:
    """의미를 바꾸지 않는 부분만 줄인 소스. 줄인 자리에는 [L시작-L끝 생략: 설명] 을 남긴다."""
    lines = text.splitlines()
    regions = []   # (시작 줄, 끝 줄, 종류, 자료)
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        tree = None
    if tree is not None:
        regions = _python_regions(tree, lines)
    regions += _data_line_regions(lines, regions)
    return _render(lines, regions, name)


def _python_regions(tree, lines) -> list:
    regions = []
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                docstrings.add(id(first.value))

    # 1) 어디서도 부르지 않는 최상위 함수: 동적 호출(getattr, eval ...)이 보이면 하지 않는다
    names_used = set()
    strings = set()
    dynamic = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            names_used.add(node.id)
            dynamic |= node.id in _DYNAMIC
        elif isinstance(node, ast.Attribute):
            names_used.add(node.attr)
            dynamic |= node.attr in _DYNAMIC or node.attr in ("__dict__", "__getattribute__")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.add(node.value)
    if not dynamic and "__all__" not in names_used:
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.decorator_list \
                    and node.name not in names_used and node.name not in strings and not node.name.startswith("__") \
                    and node.body[0].lineno > node.lineno:
                regions.append((node.body[0].lineno, node.end_lineno, "body",
                                f"어디서도 부르지 않는 함수 {node.name}"))

    # 2) 글자만 출력하는 print 가 이어지는 곳 (배너·메뉴)
    def plain_print(stmt):
        return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) and _name(stmt.value) == "print" \
            and all(isinstance(a, ast.Constant) and isinstance(a.value, str) for a in stmt.value.args) \
            and not stmt.value.keywords

    for node in ast.walk(tree):
        for attr in ("body", "orelse", "finalbody"):
            body = getattr(node, attr, None)
            if not isinstance(body, list):
                continue
            run = []
            for stmt in body + [None]:
                if stmt is not None and plain_print(stmt):
                    run.append(stmt)
                    continue
                if len(run) >= MIN_PRINTS:
                    regions.append((run[0].lineno, run[-1].end_lineno, "lines", f"글자만 출력하는 print {len(run)}개"))
                run = []

    # 3) 큰 상수 (표, 데이터, 배너 글자)
    for node in ast.walk(tree):
        desc = None
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            values = _flat_consts(node)
            if values is not None:
                desc = _table_desc(values)
        elif isinstance(node, ast.Dict) and len(node.keys) >= MIN_TABLE and \
                all(isinstance(x, ast.Constant) for x in node.keys + node.values if x is not None):
            desc = f"사전 {len(node.keys)}개 항목"
        elif isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)) and \
                len(node.value) >= MIN_STRING and id(node) not in docstrings:
            kind = _string_kind(node.value)
            if kind:
                desc = f"{kind} {len(node.value)}자"
        if desc:
            regions.append((node.lineno, node.end_lineno, "inline",
                            (node.col_offset, node.end_col_offset, desc)))
    return regions


_DATA_LINE = re.compile(r"[\s0-9a-fA-FxX,{}\[\]()'\";\\]+")


def _data_line_regions(lines, taken) -> list:
    """숫자만 늘어선 줄이 이어지는 곳 (C 배열, 파이썬이 아닌 소스, 문법이 깨진 소스)."""
    busy = set()
    for start, end, *_ in taken:
        busy.update(range(start, end + 1))
    regions, run, count = [], [], 0

    def flush():
        if run and count >= MIN_TABLE:
            regions.append((run[0], run[-1], "lines", f"숫자 {count}개가 늘어선 데이터"))

    for i, line in enumerate(lines, 1):
        numbers = len(re.findall(r"\b(?:0x[0-9a-fA-F]+|\d+)\b", line))
        if i not in busy and numbers >= 8 and _DATA_LINE.fullmatch(line):
            run.append(i)
            count += numbers
            continue
        flush()
        run, count = [], 0
    flush()
    return regions


def _render(lines, regions, name) -> Compacted:
    # 바깥 것이 먼저 오게 정렬하고, 이미 정한 영역과 겹치는 것은 버린다
    regions = sorted(regions, key=lambda r: (r[0], -r[1]))
    chosen, last = [], 0
    for region in regions:
        if region[0] > last:
            chosen.append(region)
            last = region[1]
    out, elided, i = [], [], 1
    by_start = {r[0]: r for r in chosen}
    while i <= len(lines):
        region = by_start.get(i)
        if region is None:
            out.append(lines[i - 1])
            i += 1
            continue
        start, end, kind, data = region
        if kind == "inline":
            col, end_col, desc = data
            head = lines[start - 1][:_col(lines[start - 1], col)]
            tail = lines[end - 1][_col(lines[end - 1], end_col):]
            span = f"L{start}" if start == end else f"L{start}-L{end}"
            out.append(f"{head}<{desc}, 원본 {span}>{tail}")
            elided.append((start, end, desc))
        else:
            indent = re.match(r"\s*", lines[start - 1]).group(0)
            marker = "#" if not name.endswith((".c", ".h", ".cpp", ".cc", ".js", ".ts", ".java", ".go", ".rs", ".sol")) \
                else "//"
            text = f"{indent}{'... ' if kind == 'body' else ''}{marker} [L{start}-L{end} 생략: {data}]"
            out.append(text)
            elided.append((start, end, data))
        i = end + 1
    body = "\n".join(out) + "\n"
    return Compacted(body, len(lines), elided)
