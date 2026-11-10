"""ctfkit pwn: 포너블 보조 — 보호 기법 확인(checksec) / cyclic 패턴 / ROP 가젯.

checksec·cyclic 은 표준 라이브러리만으로 동작한다(ctfkit.binfmt). rop 는 capstone 이
있으면 켜지는 선택 기능이다(`pip install ".[rev]"`). 로컬 파일 정적 분석까지만 다루고,
익스플로잇 자동화나 원격 공격은 포함하지 않는다.
"""

import sys

from ctfkit.console import log
from ctfkit.registry import TransformError

GUI_HINTS = {
    "pwn": {
        "label": "포너블",
        "order": 46,
        "desc": "보호 기법(checksec), cyclic 오프셋, ROP 가젯(capstone 선택).",
        "actions": {"checksec": "보호 기법", "cyclic": "패턴", "rop": "가젯 검색"},
        "fields": {
            "file": {"label": "바이너리 파일"},
            "length": {"label": "패턴 길이"},
            "lookup": {"label": "오프셋 찾을 값 (예: faaa 또는 0x61616166)"},
            "filter": {"label": "가젯 필터 (예: pop rdi)"},
            "depth": {"label": "가젯 최대 바이트", "default": "10"},
        },
    },
}

# cyclic 기본 알파벳·부분열 길이 (pwntools 기본과 동일: 소문자, n=4)
_ALPHABET = b"abcdefghijklmnopqrstuvwxyz"
_N = 4

_DLL_CHARACTERISTICS = [
    (0x0020, "HIGH_ENTROPY_VA (64bit ASLR)"),
    (0x0040, "DYNAMIC_BASE (ASLR)"),
    (0x0100, "NX_COMPAT (DEP)"),
    (0x0400, "NO_SEH"),
    (0x2000, "GUARD_CF (CFG)"),
]


def register(subparsers):
    parser = subparsers.add_parser("pwn", help="보호 기법·cyclic 패턴·ROP 가젯")
    actions = parser.add_subparsers(dest="action", required=True, metavar="<action>")

    p_cs = actions.add_parser("checksec", help="실행 파일 보호 기법 확인 (NX/PIE/Canary/RELRO)")
    p_cs.add_argument("file", help="바이너리 파일 경로")
    p_cs.set_defaults(func=_checksec)

    p_cy = actions.add_parser("cyclic", help="de Bruijn 패턴 생성 / 오프셋 역산")
    p_cy.add_argument("length", nargs="?", type=int, help="생성할 패턴 길이")
    p_cy.add_argument(
        "-l", "--lookup",
        help="이 값이 패턴에서 처음 나오는 오프셋을 찾는다 (문자열 'faaa' 또는 '0x..' 리틀엔디언)",
    )
    p_cy.add_argument("-n", "--size", type=int, default=_N, help=f"부분열 길이(워드 크기, 기본 {_N})")
    p_cy.set_defaults(func=_cyclic)

    p_rop = actions.add_parser("rop", help="ret 로 끝나는 ROP 가젯 검색 (capstone 필요, x86/x64)")
    p_rop.add_argument("file", help="바이너리 파일 경로")
    p_rop.add_argument("-f", "--filter", help="이 문자열을 포함하는 가젯만 (예: 'pop rdi')")
    p_rop.add_argument("--depth", type=int, default=10, help="ret 앞으로 살펴볼 최대 바이트 (기본 10)")
    p_rop.set_defaults(func=_rop)


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# ---------- checksec ----------

def _checksec(args):
    from ctfkit import binfmt   # checksec·rop 에서만 필요하다 (cyclic 시작 시간 절약)
    info = binfmt.parse(_read(args.file))
    if info.fmt == "ELF":
        return _checksec_elf(info)
    return _checksec_pe(info)


def _mark(ok: bool, yes="O", no="X") -> str:
    return yes if ok else no


def _checksec_elf(info) -> int:
    from ctfkit import binfmt   # checksec·rop 에서만 필요하다 (cyclic 시작 시간 절약)
    # NX: GNU_STACK 세그먼트가 실행 권한이 없으면 NX 켜짐
    gnu_stack = next((s for s in info.segments if s.type == binfmt.PT_GNU_STACK), None)
    if gnu_stack is None:
        nx = "표시 없음 (GNU_STACK 세그먼트 없음)"
    else:
        nx = _mark(not (gnu_stack.flags & binfmt.PF_X), "켜짐", "꺼짐(실행 가능 스택)")

    # PIE: 실행 파일 타입이 DYN(3) 이면 PIE
    pie = _mark(info.extra.get("e_type") == 3, "켜짐", "꺼짐 (No PIE)")

    # Canary: __stack_chk_fail 심볼이 있으면 스택 카나리 사용
    canary = "켜짐" if any(s.name == "__stack_chk_fail" for s in info.symbols) else "꺼짐"

    # RELRO: GNU_RELRO 세그먼트가 있으면 Partial, BIND_NOW 까지면 Full
    has_relro = any(s.type == binfmt.PT_GNU_RELRO for s in info.segments)
    bind_now = (
        binfmt.DT_BIND_NOW in info.dynamic
        or (info.dynamic.get(binfmt.DT_FLAGS, 0) & binfmt.DF_BIND_NOW)
        or (info.dynamic.get(binfmt.DT_FLAGS_1, 0) & binfmt.DF_1_NOW)
    )
    if not has_relro:
        relro = "없음 (No RELRO)"
    else:
        relro = "Full RELRO" if bind_now else "Partial RELRO"

    print(f"파일   : {info.fmt} {info.bits}-bit  {info.machine}  ({info.kind})")
    print(f"NX     : {nx}")
    print(f"PIE    : {pie}")
    print(f"Canary : {canary}")
    print(f"RELRO  : {relro}")
    return 0


def _checksec_pe(info) -> int:
    dll = info.extra.get("dll_characteristics", 0)
    print(f"파일   : {info.fmt} {info.bits}-bit  {info.machine}  ({info.kind})")
    print(f"DllCharacteristics: 0x{dll:04x}")
    for bit, label in _DLL_CHARACTERISTICS:
        print(f"  {_mark(bool(dll & bit))} {label}")
    return 0


# ---------- cyclic ----------

def de_bruijn(alphabet: bytes, n: int) -> bytes:
    """de Bruijn 수열 B(k, n) 전체를 만든다 (pwntools cyclic 과 같은 방식).

    길이 n 짜리 부분열이 모두 정확히 한 번씩만 나타나므로, 패턴 어디서 겹쳐 썼는지
    (오프셋)를 역산할 수 있다.
    """
    k = len(alphabet)
    a = [0] * (k * n)
    seq = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                seq.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return bytes(alphabet[i] for i in seq)


def _cyclic(args):
    n = args.size
    if n < 1:
        raise TransformError("--size 는 1 이상이어야 합니다")
    maxlen = len(_ALPHABET) ** n

    if args.lookup is not None:
        sub = _lookup_bytes(args.lookup)
        if len(sub) != n:
            raise TransformError(f"찾는 값은 {n}바이트여야 합니다 (받은 길이: {len(sub)})")
        pattern = de_bruijn(_ALPHABET, n)
        idx = pattern.find(sub)
        if idx < 0:
            raise TransformError("패턴에서 찾지 못했습니다 (cyclic 으로 만든 값이 맞는지 확인)")
        print(idx)
        return 0

    if args.length is None:
        raise TransformError("생성할 길이를 주거나 --lookup 으로 오프셋을 찾으세요")
    if args.length > maxlen:
        raise TransformError(
            f"요청 길이 {args.length} 가 n={n} 으로 만들 수 있는 최대({maxlen})를 넘습니다. -n 을 키우세요"
        )
    sys.stdout.buffer.write(de_bruijn(_ALPHABET, n)[:args.length])
    sys.stdout.write("\n")
    return 0


def _lookup_bytes(value: str) -> bytes:
    """오프셋 조회 값을 bytes 로. '0x..' 면 리틀엔디언 정수로, 아니면 ASCII 문자열로 해석."""
    if value[:2].lower() == "0x":
        try:
            num = int(value, 16)
        except ValueError as e:
            raise TransformError(f"잘못된 16진수 값: {value} ({e})") from e
        length = max(1, (len(value) - 2 + 1) // 2)
        return num.to_bytes(length, "little")
    return value.encode("utf-8")


# ---------- rop ----------

def _rop(args):
    try:
        import capstone
    except ImportError:
        raise TransformError(
            "rop 에는 capstone 이 필요합니다. `pip install capstone` (또는 `pip install \".[rev]\"`) 후 다시 시도하세요"
        ) from None

    data = _read(args.file)
    from ctfkit import binfmt   # checksec·rop 에서만 필요하다 (cyclic 시작 시간 절약)
    info = binfmt.parse(data)
    if info.arch not in ("x86", "x64"):
        raise TransformError(f"rop 은 x86/x64 만 지원합니다 (이 파일: {info.machine})")
    mode = capstone.CS_MODE_64 if info.arch == "x64" else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)

    # 실행 세그먼트가 없으면(섹션만 있는 오브젝트 등) 실행 섹션으로 대체
    regions = [(s.vaddr, data[s.offset:s.offset + s.filesz]) for s in info.exec_segments()]
    if not regions:
        regions = [
            (s.addr, data[s.offset:s.offset + s.filesize])
            for s in info.sections if s.name in (".text", ".plt", ".init", ".fini") and s.filesize
        ]
    if not regions:
        raise TransformError("실행 가능한 영역을 찾지 못했습니다")

    gadgets = _find_gadgets(md, regions, args.depth)
    needle = args.filter
    shown = 0
    for addr, text in sorted(gadgets.items()):
        if needle and needle not in text:
            continue
        print(f"0x{addr:08x} : {text}")
        shown += 1
    if shown == 0:
        log("(조건에 맞는 가젯이 없습니다)")
        return 1
    return 0


def _find_gadgets(md, regions, depth: int) -> dict:
    """각 ret(0xc3) 앞의 바이트를 디스어셈블해 유효한 가젯을 모은다. {주소: 텍스트}."""
    gadgets = {}
    for base, blob in regions:
        for i, byte in enumerate(blob):
            if byte != 0xC3:  # ret
                continue
            for start in range(max(0, i - depth), i + 1):
                window = blob[start:i + 1]
                insns = list(md.disasm(window, base + start))
                # 창 전체가 빈틈없이 디코드되고, 마지막이 ret 로 끝나야 유효한 가젯
                if not insns:
                    continue
                if sum(ins.size for ins in insns) != len(window):
                    continue
                if insns[-1].mnemonic != "ret":
                    continue
                text = " ; ".join(
                    f"{ins.mnemonic} {ins.op_str}".strip() for ins in insns
                )
                gadgets.setdefault(base + start, text)
    return gadgets
