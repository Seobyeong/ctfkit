"""ctfkit brief: AI 에이전트가 읽을 짧은 요약 (start 가 AGENTS.md 에 적는 것을 파일 하나에 대해).

  brief SOURCE          소스의 사실, 성립하지 않는 공격(제외), 전제 조건이 보이는 공격(후보)
  brief SOURCE --code   의미 없는 부분만 줄인 소스 (줄인 자리에 원본 줄 번호를 남긴다)
  brief VALUES.txt      글자 파일의 '이름 = 정수' 값 목록과, n·e·c 가 있으면 가벼운 RSA 공격을 직접 해 본 결과

사람이 읽을 출력이 아니다. 형식은 한 줄에 하나, 앞에 종류(사실/제외/후보/시도/값)를 붙인다.
"""

import os

from ctfkit import brief, source
from ctfkit.registry import TransformError

GUI_HINTS = {
    "brief": {
        "label": "AI 요약",
        "order": 49,
        "group": "파일·바이너리",
        "desc": "AI 에이전트용: 소스에서 성립하지 않는 공격, 줄인 소스, 값 파일을 보여 줍니다.",
        "actions": {},
        "fields": {
            "file": {"label": "소스 또는 값 파일", "kind": "file"},
            "code": {"label": "줄인 소스 출력"},
        },
    },
}

MAX_SIZE = 4 * 1024 * 1024


def register(subparsers):
    p = subparsers.add_parser("brief", help="AI 에이전트용 요약: 소스의 제외·후보 공격, 줄인 소스(--code), 값 파일")
    p.add_argument("file", help="소스 코드 또는 값이 적힌 글자 파일 (output.txt 등)")
    p.add_argument("--code", action="store_true", help="요약 대신 의미 없는 부분만 줄인 소스를 출력")
    p.set_defaults(func=_run)


def _run(args):
    try:
        if os.path.getsize(args.file) > MAX_SIZE:
            raise TransformError(f"파일이 너무 큽니다 (상한 {MAX_SIZE // 1024 // 1024}MB)")
        with open(args.file, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        raise TransformError(f"파일을 읽을 수 없습니다: {e}") from e
    name = os.path.basename(args.file)
    lang = source.language(text, name)

    if args.code:
        small = brief.compact(text, name)
        print(f"# ctfkit brief: {name} {small.original_lines}줄 → {small.kept_lines}줄. "
              f"[Lx-Ly 생략] 은 원본 줄 번호", flush=True)
        print(small.text, end="")
        return 0

    if lang is not None:
        sb = brief.analyze_source(text, name) if lang == "Python" else None
        if sb is None:
            info = source.analyze(text, name)
            print(f"언어: {lang} (성립하지 않는 공격 판정은 파이썬 소스만)")
            if info and info.clues:
                print("단서: " + ", ".join(info.clues))
            return 1
        lines = sb.lines()
        for line in lines:
            print(line)
        if not lines:
            print("판정할 것 없음 (RSA·블록 암호·난수·입력 관련 코드가 보이지 않음)")
        return 0 if lines else 1

    values = brief.extract_values(text)
    if not values:
        print("값 없음 ('이름 = 정수' 꼴의 줄이 없음)")
        return 1
    store, origins = {}, {}
    brief.merge_values(store, origins, values, name)
    print("값: " + ", ".join(brief.describe_value(k, v) for k, v in store.items()))
    tried, plain = brief.try_rsa(store)
    for line in tried:
        print(f"시도: {line}")
    if plain is not None:
        print(f"평문: {plain!r}")
    return 0
