"""ctfkit rev: 실행 파일(ELF/PE) 정적 분석 — 정보 요약 / 디스어셈블.

info 는 표준 라이브러리만으로 동작한다(ctfkit.binfmt). disasm 은 capstone 이
있으면 켜지는 선택 기능이다(`pip install ".[rev]"`). 원격 익스플로잇은 다루지 않고,
로컬 파일의 정적 분석까지만 한다.
"""

import sys

from ctfkit import binfmt
from ctfkit.console import log
from ctfkit.registry import TransformError

GUI_HINTS = {
    "rev": {
        "label": "리버싱",
        "order": 45,
        "desc": "ELF/PE 아키텍처·섹션·심볼 요약과 디스어셈블(capstone 선택).",
        "actions": {"info": "정보 요약", "disasm": "디스어셈블"},
        "fields": {
            "file": {"label": "바이너리 파일"},
            "count": {"label": "명령 개수", "default": "32"},
            "offset": {"label": "시작 (0x주소 또는 +파일오프셋, 비우면 entry)", "default": ""},
        },
    },
}

# binfmt 아키텍처 키 -> capstone (arch, mode) 상수 이름. 실행 시점에 capstone 을 import 한다.
_CAPSTONE_ARCH = {
    "x86": ("CS_ARCH_X86", "CS_MODE_32"),
    "x64": ("CS_ARCH_X86", "CS_MODE_64"),
    "arm": ("CS_ARCH_ARM", "CS_MODE_ARM"),
    "arm64": ("CS_ARCH_ARM64", "CS_MODE_ARM"),
    "mips": ("CS_ARCH_MIPS", "CS_MODE_32"),
}


def register(subparsers):
    parser = subparsers.add_parser("rev", help="ELF/PE 정보 요약·디스어셈블")
    actions = parser.add_subparsers(dest="action", required=True, metavar="<action>")

    p_info = actions.add_parser("info", help="아키텍처·섹션·심볼 요약")
    p_info.add_argument("file", help="바이너리 파일 경로")
    p_info.add_argument("--sections", action="store_true", help="섹션 목록도 모두 출력")
    p_info.set_defaults(func=_info)

    p_dis = actions.add_parser("disasm", help="디스어셈블 (capstone 필요)")
    p_dis.add_argument("file", help="바이너리 파일 경로")
    p_dis.add_argument(
        "--offset", help="시작 위치. '0x..' 면 가상주소, '+N' 이면 파일 오프셋 (비우면 entry)",
    )
    p_dis.add_argument("-n", "--count", type=int, default=32, help="디스어셈블할 명령 개수 (기본 32)")
    p_dis.set_defaults(func=_disasm)


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _info(args):
    info = binfmt.parse(_read(args.file))
    print(f"형식    : {info.fmt} {info.bits}-bit ({info.endian}-endian)")
    print(f"아키텍처: {info.machine}" + ("" if info.arch else "  [disasm 미지원]"))
    print(f"종류    : {info.kind}")
    print(f"entry   : 0x{info.entry:x}")
    print(f"섹션    : {len(info.sections)}개, 심볼(함수/객체): {len(info.symbols)}개")

    if args.sections and info.sections:
        print("\n[섹션]")
        print(f"  {'이름':<18} {'주소':>12} {'오프셋':>10} {'크기':>10}")
        for s in info.sections:
            print(f"  {s.name:<18} {s.addr:>12x} {s.offset:>10x} {s.size:>10x}")

    funcs = [s for s in info.symbols if s.kind == "FUNC"]
    if funcs:
        print(f"\n[함수 심볼] {len(funcs)}개 (주소 순 상위 20)")
        for s in sorted(funcs, key=lambda x: x.addr)[:20]:
            print(f"  0x{s.addr:08x}  {s.name}")
    return 0


def _resolve_start(info, arg: str | None):
    """시작 위치 인자를 (가상주소, 파일오프셋, 읽을수있는최대바이트) 로 해석한다."""
    if arg is None or arg == "":
        vaddr = info.entry
        sec = info.section_at(vaddr)
        if sec is None:
            raise TransformError(
                f"entry(0x{info.entry:x}) 를 담은 섹션을 찾지 못했습니다. --offset 으로 직접 지정하세요"
            )
        file_off = sec.offset + (vaddr - sec.addr)
        avail = sec.filesize - (vaddr - sec.addr)
        return vaddr, file_off, avail
    if arg.startswith("+"):
        file_off = int(arg[1:], 0)
        return file_off, file_off, None   # 파일 오프셋 지정: 주소는 오프셋으로 표기
    vaddr = int(arg, 0)
    sec = info.section_at(vaddr)
    if sec is None:
        raise TransformError(f"주소 0x{vaddr:x} 를 담은 섹션이 없습니다")
    file_off = sec.offset + (vaddr - sec.addr)
    avail = sec.filesize - (vaddr - sec.addr)
    return vaddr, file_off, avail


def _disasm(args):
    try:
        import capstone
    except ImportError:
        raise TransformError(
            "disasm 에는 capstone 이 필요합니다. `pip install capstone` (또는 `pip install \".[rev]\"`) 후 다시 시도하세요"
        ) from None

    data = _read(args.file)
    info = binfmt.parse(data)
    if info.arch not in _CAPSTONE_ARCH:
        raise TransformError(f"disasm 을 지원하지 않는 아키텍처입니다: {info.machine}")

    arch_name, mode_name = _CAPSTONE_ARCH[info.arch]
    md = capstone.Cs(getattr(capstone, arch_name), getattr(capstone, mode_name))

    vaddr, file_off, avail = _resolve_start(info, args.offset)
    if file_off >= len(data):
        raise TransformError(f"시작 오프셋(0x{file_off:x})이 파일 크기를 넘습니다")
    # 명령 1개 최대 15바이트 기준으로 넉넉히 읽고, 섹션 끝/파일 끝에서 자른다
    end = len(data) if avail is None else min(len(data), file_off + avail)
    chunk = data[file_off:min(end, file_off + args.count * 15)]

    count = 0
    for insn in md.disasm(chunk, vaddr):
        print(f"0x{insn.address:08x}  {insn.mnemonic:<8} {insn.op_str}")
        count += 1
        if count >= args.count:
            break
    if count == 0:
        log("(디스어셈블된 명령이 없습니다 — 코드 영역이 아니거나 아키텍처가 맞지 않을 수 있습니다)")
        return 1
    return 0
