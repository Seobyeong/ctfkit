"""ctfkit triage: 파일 하나를 받아 "처음에 해 볼 것들" 을 한 번에 돌리고 요약한다.

파일 문제를 받으면 보통 형식 확인 → 플래그 문자열 검색 → 숨은 파일 → ZIP 내용 → 메타데이터 →
(실행 파일이면) 보호 기법 순으로 명령을 여러 번 실행한다. AI 에이전트에게는 그 한 번 한 번이
왕복(결과를 읽고 다음 명령을 정하는 과정)이라 비용이 크다. triage 는 이 순서를 한 번의 호출로 묶는다.

새로 분석하는 것은 없다. forensic / exif / binfmt / pwn / auto 엔진의 함수를 불러 결과만 모은다.
"""

import zipfile

from ctfkit.commands.forensic import _read_file, find_embedded, identify
from ctfkit.console import is_quiet, log, preview
from ctfkit.flags import EMBEDDED_FLAG_PATTERN, compile_flag_pattern
from ctfkit.registry import TransformError

# 한 번의 호출이 끝없이 커지지 않게 하는 상한들
MAX_MEMBERS = 50                 # ZIP 에서 열어 볼 항목 수
MAX_MEMBER_SIZE = 1024 * 1024    # 이보다 큰 항목은 내용을 읽지 않는다 (압축 폭탄 방지)
MAX_AUTO_SIZE = 4096             # 이보다 작은 글자 데이터만 auto 로 디코딩을 시도한다
MAX_LIST = 8                     # 목록(ZIP 항목, EXIF 태그, 숨은 파일)을 몇 줄까지 보여 줄지

GUI_HINTS = {
    "triage": {
        "label": "파일 한 번에 분석",
        "order": 5,
        "desc": "형식·플래그·숨은 파일·ZIP 내용·메타데이터·보호 기법을 한 번에 요약합니다.",
        "actions": {},
        "fields": {
            "file": {"label": "파일", "kind": "file"},
            "flag": {"label": "플래그 정규식"},
        },
    },
}


def register(subparsers):
    p = subparsers.add_parser("triage", help="파일을 한 번에 분석해 요약 (형식·플래그·숨은 파일·보호 기법)")
    p.add_argument("file", help="분석할 파일")
    p.add_argument("--flag", metavar="REGEX", help="플래그 정규식 (기본: DH{...} 등)")
    p.set_defaults(func=_run)


class Report:
    """분석 결과를 모으는 통. 플래그는 (값, 찾은 곳) 으로, 나머지는 '이름: 값' 줄로 쌓는다."""

    def __init__(self, pattern):
        self.pattern = pattern
        self.flags: list[tuple[str, str]] = []
        self.lines: list[str] = []

    def add(self, key: str, value: str) -> None:
        self.lines.append(f"{key}: {value}")

    def scan(self, data: bytes, where: str) -> bool:
        """data 에서 플래그를 찾아 기록한다. 하나라도 찾았으면 True."""
        found = False
        for match in self.pattern.finditer(data):
            flag = match.group(0).decode("ascii", "replace")
            found = True
            if all(flag != seen for seen, _ in self.flags):
                self.flags.append((flag, where))
        return found

    def try_decode(self, data: bytes, where: str) -> None:
        """플래그가 안 보이는 짧은 글자 데이터면 auto 엔진으로 디코딩해 본다."""
        text = data.strip()
        if not text or len(text) > MAX_AUTO_SIZE or not _is_text(text):
            return
        from ctfkit.engine import search   # 필요할 때만 불러온다 (변환 전체를 import 하므로 무겁다)

        results = search(text, depth=4, flag_pattern=self.pattern.pattern.decode())
        if results and results[0].flag:
            path = "→".join(step.transform for step in results[0].steps)
            flag = results[0].flag.decode("ascii", "replace")
            if all(flag != seen for seen, _ in self.flags):
                self.flags.append((flag, f"{where} ({path})"))


def _is_text(data: bytes) -> bool:
    return all(0x20 <= b <= 0x7E or b in b"\r\n\t" for b in data)


def _shorten(items: list[str]) -> str:
    """목록을 MAX_LIST 개까지만 잇고, 나머지는 개수로 줄인다."""
    shown = ", ".join(items[:MAX_LIST])
    return shown if len(items) <= MAX_LIST else f"{shown} 외 {len(items) - MAX_LIST}개"


# ---------------------------------------------------------------- 분석 단계

def _check_zip(path: str, report: Report) -> None:
    """ZIP 항목을 풀어 플래그를 찾는다. zipfile 은 앞에 다른 데이터가 붙은 파일(PNG+ZIP)도 읽는다."""
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return
    with zf:
        infos = zf.infolist()
        names, locked = [], 0
        for info in infos[:MAX_MEMBERS]:
            names.append(f"{info.filename}({info.file_size})")
            if info.is_dir() or info.file_size > MAX_MEMBER_SIZE:
                continue
            if info.flag_bits & 0x1:
                locked += 1
                continue
            try:
                content = zf.read(info)
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError):
                continue
            where = f"ZIP:{info.filename}"
            if not report.scan(content, where):
                report.try_decode(content, where)
    if names:
        report.add("ZIP", _shorten(names))
    if locked:
        report.add("ZIP 암호", f"{locked}개 항목이 암호로 잠김")


def _check_exif(data: bytes, report: Report) -> None:
    from ctfkit import exif

    try:
        tags = exif.parse_exif(data)
    except (TransformError, ValueError, IndexError):
        return
    except Exception:   # 손상된 EXIF 가 요약 전체를 막지 않게 한다
        return
    for name, value in tags:
        report.scan(str(value).encode("utf-8", "replace"), f"EXIF:{name}")
    if tags:
        report.add("EXIF", _shorten([f"{name}={preview(str(value).encode('utf-8', 'replace'), 40)}"
                                     for name, value in tags]))


def _check_binary(data: bytes, report: Report) -> None:
    from ctfkit import binfmt
    from ctfkit.commands.pwn import elf_protections

    try:
        info = binfmt.parse(data)
    except (TransformError, ValueError, IndexError):
        return
    except Exception:   # 손상된 헤더가 요약 전체를 막지 않게 한다
        return
    report.add("실행 파일", f"{info.fmt} {info.bits}-bit {info.machine} ({info.kind})")
    if info.fmt == "ELF":
        report.add("보호 기법", ", ".join(value if name in value else f"{name} {value}"
                                      for name, value in elf_protections(info)))
    funcs = [s.name for s in info.symbols if s.kind == "FUNC" and s.name]
    if funcs:
        report.add("함수", _shorten(funcs))


def _next_steps(fmt: str | None, report: Report) -> None:
    """플래그를 못 찾았을 때, 형식에 따라 다음에 해 볼 명령을 한 줄로 알려 준다."""
    fmt = fmt or ""
    tips = []
    if "이미지" in fmt:
        tips.append("forensic lsb <파일>")
    if "ELF" in fmt or "PE" in fmt:
        tips += ["rev disasm <파일>", "pwn rop <파일>"]
    tips.append("forensic strings <파일> --grep <정규식>")
    report.add("다음", " / ".join(tips))


# ---------------------------------------------------------------- 실행

def _run(args):
    data = _read_file(args.file)
    try:
        pattern = compile_flag_pattern(args.flag or EMBEDDED_FLAG_PATTERN)
    except ValueError as e:
        raise TransformError(str(e)) from e
    report = Report(pattern)

    fmt = identify(data)
    report.add("형식", f"{fmt or '알 수 없음'} ({len(data)} 바이트)")

    if not report.scan(data, "파일 본문"):
        report.try_decode(data, "파일 본문")

    embedded = find_embedded(data)
    if embedded:
        report.add("숨은 파일", _shorten([f"{off:#x} {name}" for off, name in embedded]))

    if (fmt or "").startswith("ZIP") or any(name == "ZIP" for _, name in embedded):
        _check_zip(args.file, report)
    if data[:3] == b"\xff\xd8\xff" or data[:2] in (b"II", b"MM"):
        _check_exif(data, report)
    if data[:4] == b"\x7fELF" or data[:2] == b"MZ":
        _check_binary(data, report)

    if report.flags:
        # 답만: --quiet 면 플래그만 한 줄씩
        for flag, where in report.flags:
            print(flag if is_quiet() else f"플래그: {flag}  [{where}]")
        if is_quiet():
            return 0
    else:
        _next_steps(fmt, report)
        log("[-] 플래그를 찾지 못했습니다. 아래 요약과 '다음' 줄을 참고하세요.")

    for line in report.lines:
        print(line)
    return 0
