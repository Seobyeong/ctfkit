"""ctfkit doctor: 외부 도구가 설치돼 있는지, 없으면 무엇을 못 하는지 한 화면으로 보여 준다.

triage·start 는 설치된 외부 도구(binwalk, exiftool 등)가 있으면 함께 쓰고, 없으면 내장 구현으로 대신한다.
결과가 기대보다 적을 때 "도구가 없어서인가" 를 바로 확인할 수 있게 한다. 파이썬 선택 의존성(Pillow, capstone)도 함께 본다.
"""

import importlib.util

from ctfkit import external
from ctfkit.console import log

GUI_HINTS = {
    "doctor": {
        "label": "외부 도구 확인",
        "order": 80,
        "group": "작업",
        "desc": "triage·start 가 함께 쓰는 외부 도구가 설치돼 있는지 확인합니다.",
        "actions": {},
        "fields": {},
    },
}

# (모듈 이름, pip 패키지, 쓰는 곳)
_PY_EXTRAS = [
    ("PIL", "pillow", "forensic lsb (이미지 LSB 추출)"),
    ("capstone", "capstone", "rev disasm (디스어셈블)"),
]


def register(subparsers):
    p = subparsers.add_parser("doctor", help="외부 도구(binwalk, exiftool, zsteg 등) 설치 상태 확인")
    p.set_defaults(func=_run)


def _run(args):
    if external.disabled():
        log("[i] CTFKIT_NO_EXTERNAL 이 켜져 있어 triage·start 가 외부 도구를 쓰지 않습니다.")

    missing = []
    print("외부 도구 (triage·start 가 있으면 함께 씀)")
    for tool in external.TOOLS:
        path = external.find(tool.name)
        if path:
            print(f"  [O] {tool.name:<9} {tool.use}  ({path})")
        else:
            missing.append(tool.name)
            print(f"  [ ] {tool.name:<9} {tool.use}  → 없으면: {tool.fallback}")

    print("파이썬 선택 의존성")
    for module, package, use in _PY_EXTRAS:
        mark = "O" if importlib.util.find_spec(module) else " "
        hint = "" if mark == "O" else f"  → pip install {package}"
        print(f"  [{mark}] {package:<9} {use}{hint}")

    if missing:
        log(f"[i] 없는 도구 {len(missing)}개. 없어도 동작하지만 결과가 줄어듭니다. "
            "리눅스(WSL): sudo apt install binutils file libimage-exiftool-perl binwalk tshark checksec && sudo gem install zsteg")
    return 0
