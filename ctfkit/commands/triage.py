"""ctfkit triage: 파일 하나를 받아 "처음에 해 볼 것들" 을 한 번에 돌리고 요약한다.

파일 문제를 받으면 보통 형식 확인 → 플래그 문자열 검색 → 숨은 파일 → ZIP 내용 → 메타데이터 →
(실행 파일이면) 보호 기법 순으로 명령을 여러 번 실행한다. AI 에이전트에게는 그 한 번 한 번이
왕복(결과를 읽고 다음 명령을 정하는 과정)이라 비용이 크다. triage 는 이 순서를 한 번의 호출로 묶는다.

새로 분석하는 것은 없다. forensic / exif / binfmt / pwn / auto 엔진의 함수를 불러 결과만 모은다.
설치된 외부 도구(file, strings, exiftool, binwalk, zsteg, checksec, tshark)가 있으면 함께 돌리고, 출력에서
플래그와 눈에 띄는 줄만 추린다. 외부 도구가 낸 결과는 항목 이름에 도구 이름을 붙여 구분한다 (예: "binwalk").
"""

import re
import zipfile

from ctfkit import external

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
        "group": "시작",
        "desc": "형식·플래그·숨은 파일·ZIP 내용·메타데이터·보호 기법을 한 번에 요약합니다.",
        "actions": {},
        "fields": {
            "file": {"label": "파일", "kind": "file"},
            "flag": {"label": "플래그 정규식"},
            "json": {"label": "JSON 으로 출력"},
            "no_external": {"label": "외부 도구 쓰지 않기"},
        },
    },
}


def register(subparsers):
    p = subparsers.add_parser("triage", help="파일을 한 번에 분석해 요약 (형식·플래그·숨은 파일·보호 기법)")
    p.add_argument("file", help="분석할 파일")
    p.add_argument("--flag", metavar="REGEX", help="플래그 정규식 (기본: DH{...} 등)")
    p.add_argument("--json", action="store_true", help="결과를 JSON 한 줄로 출력 (프로그램·에이전트가 읽기 좋게)")
    p.add_argument("--no-external", action="store_true",
                   help="설치된 외부 도구(binwalk, exiftool 등)를 쓰지 않고 내장 분석만")
    p.set_defaults(func=_run)


class Report:
    """분석 결과를 모으는 통. 플래그는 (값, 찾은 곳) 으로, 나머지는 '이름: 값' 줄로 쌓는다."""

    def __init__(self, pattern):
        self.pattern = pattern
        self.fmt: str | None = None   # 판별한 파일 형식 (모르면 None)
        self.flags: list[tuple[str, str]] = []
        self.items: list[tuple[str, str]] = []
        self.missing: list[str] = []  # 이 파일에 쓸모 있었을 텐데 설치되지 않은 외부 도구

    def add(self, key: str, value: str) -> None:
        self.items.append((key, value))

    @property
    def lines(self) -> list[str]:
        return [f"{key}: {value}" for key, value in self.items]

    def to_json(self) -> str:
        import json

        return json.dumps({
            "flags": [{"flag": flag, "where": where} for flag, where in self.flags],
            "info": dict(self.items),
        }, ensure_ascii=False, separators=(",", ":"))

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


# ---------------------------------------------------------------- 외부 도구 (설치돼 있을 때만)

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# exiftool 태그 중 문제 출제자가 무언가를 숨기는 곳. 파일 크기·날짜 같은 기본 태그는 보여 주지 않는다
_EXIF_INTERESTING = ("comment", "description", "author", "artist", "creator", "title", "subject",
                     "keyword", "copyright", "warning", "text", "flag", "secret", "password", "hint")
_PROTECTION = re.compile(rb"(?:Full|Partial|No) RELRO|No canary found|Canary found|NX (?:enabled|disabled)"
                         rb"|No PIE|PIE enabled", re.IGNORECASE)
_PCAP_MAGIC = (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",
               b"\x0a\x0d\x0d\x0a")


def _tools_for(data: bytes, report: Report) -> list[str]:
    """이 파일에 돌려 볼 외부 도구. 글자 파일에는 돌리지 않는다 (내장 검색과 auto 로 충분하다)."""
    if report.fmt == "글자 파일" or not data:
        return []
    tools = ["strings", "exiftool", "binwalk"]
    if report.fmt is None:
        tools.insert(0, "file")
    if data[:8] == b"\x89PNG\r\n\x1a\n" or data[:2] == b"BM":
        tools.append("zsteg")
    if data[:4] == b"\x7fELF" and not any(key == "보호 기법" for key, _ in report.items):
        tools.append("checksec")   # 내장 파서가 읽지 못한 ELF 만
    if data[:4] in _PCAP_MAGIC:
        tools.append("tshark")
    return tools


def _lines(result) -> list[str]:
    return [_ANSI.sub("", line).rstrip() for line in result.text.splitlines() if line.strip()]


def _ext_file(path: str, report: Report) -> None:
    result = external.run("file", ["-b", path])
    if result.usable:
        line = _lines(result)[0][:100]
        if line != "data":   # file 도 모르는 형식이면 "data" 라고만 한다. 덧붙일 정보가 없다
            report.add("형식(file)", line)


def _ext_strings(path: str, report: Report) -> None:
    # 내장 검색은 1바이트 문자만 본다. 윈도 프로그램·문서에 흔한 UTF-16LE 문자열은 strings -el 로 찾는다
    result = external.run("strings", ["-a", "-el", path])
    if result.usable:
        report.scan(result.output, "strings -el (UTF-16)")


def _ext_exiftool(path: str, report: Report) -> None:
    result = external.run("exiftool", ["-S", path])
    if not result.usable:
        return
    report.scan(result.output, "exiftool")
    shown = []
    for line in _lines(result):
        tag, _, value = line.partition(":")
        if value.strip() and any(word in tag.lower() for word in _EXIF_INTERESTING):
            shown.append(f"{tag.strip()}={value.strip()[:40]}")
    if shown:
        report.add("exiftool", _shorten(shown))


def _ext_binwalk(path: str, report: Report) -> None:
    result = external.run("binwalk", [path])
    if not result.usable:
        return
    found = []
    for line in _lines(result):
        m = re.match(r"\s*(\d+)\s+0x([0-9A-Fa-f]+)\s+(.+)", line)
        if m and int(m.group(1)) > 0:   # 0 은 파일 자신
            found.append(f"{int(m.group(1)):#x} {m.group(3).split(',')[0].strip()[:40]}")
    if found:
        report.add("binwalk", _shorten(found))


def _ext_zsteg(path: str, report: Report) -> None:
    result = external.run("zsteg", [path])
    if not result.usable:
        return
    report.scan(_ANSI.sub("", result.text).encode("utf-8", "replace"), "zsteg")
    files = [line.strip()[:60] for line in _lines(result) if " file: " in line]
    if files:
        report.add("zsteg", _shorten(files))


def _ext_checksec(path: str, report: Report) -> None:
    result = external.run("checksec", [f"--file={path}"])
    if result.usable:
        found = list(dict.fromkeys(m.group(0).decode() for m in _PROTECTION.finditer(result.output)))
        if found:
            report.add("보호 기법(checksec)", ", ".join(found))


def _ext_tshark(path: str, report: Report) -> None:
    result = external.run("tshark", ["-r", path, "-q", "-z", "io,phs"])
    if not result.usable:
        return
    protocols = []
    for line in _lines(result):
        m = re.match(r"\s*([\w.-]+)\s+frames:(\d+)", line)
        if m and m.group(1) not in ("eth", "frame", "ip", "ipv6", "sll", "null"):
            protocols.append(f"{m.group(1)}({m.group(2)})")
    if protocols:
        report.add("프로토콜(tshark)", _shorten(list(dict.fromkeys(protocols))))


_EXTERNAL = {
    "file": _ext_file, "strings": _ext_strings, "exiftool": _ext_exiftool, "binwalk": _ext_binwalk,
    "zsteg": _ext_zsteg, "checksec": _ext_checksec, "tshark": _ext_tshark,
}


def _check_external(path: str, data: bytes, report: Report) -> None:
    """이 파일에 맞는 외부 도구를 돌린다. 없는 도구는 report.missing 에 적어 설치 안내에 쓴다."""
    if external.disabled():
        return
    for name in _tools_for(data, report):
        if external.find(name) is None:
            report.missing.append(name)
            continue
        try:
            _EXTERNAL[name](path, report)
        except Exception:   # 처음 보는 출력 형식이 요약 전체를 막지 않게 한다
            continue


def next_steps(fmt: str | None, path: str = "<파일>") -> list[str]:
    """플래그를 못 찾았을 때, 형식에 따라 다음에 해 볼 명령 목록."""
    fmt = fmt or ""
    tips = []
    if "이미지" in fmt:
        tips.append(f"forensic lsb {path}")
    if "ELF" in fmt:
        tips.append(f"template pwn {path}")   # 보호 기법·아키텍처가 채워진 pwntools 뼈대
    if "ELF" in fmt or "PE" in fmt:
        tips += [f"rev disasm {path}", f"pwn rop {path}"]
    tips.append(f"forensic strings {path} --grep <정규식>")
    return tips


# ---------------------------------------------------------------- 실행

def compile_pattern(flag: str | None):
    """--flag 값을 정규식으로. 파일 안에서 찾으므로 기본값은 단어 경계를 요구하지 않는 형식이다."""
    try:
        return compile_flag_pattern(flag or EMBEDDED_FLAG_PATTERN)
    except ValueError as e:
        raise TransformError(str(e)) from e


def analyze(path: str, pattern, inspect_zip: bool = True, use_external: bool = True) -> Report:
    """파일 하나를 분석해 Report 로 돌려준다. 출력은 하지 않는다 (triage 와 start 가 함께 쓴다).

    inspect_zip=False 면 ZIP 항목을 열어 보지 않는다. start 는 압축 파일을 직접 풀어 안의 파일을 하나씩
    분석하므로, 같은 내용을 두 번 보지 않게 끈다.
    use_external=False 면 외부 도구를 쓰지 않는다 (CTFKIT_NO_EXTERNAL=1 과 같다).
    """
    data = _read_file(path)
    report = Report(pattern)

    fmt = identify(data)
    if fmt is None and data.strip() and _is_text(data[:4096]):
        fmt = "글자 파일"   # 매직 바이트는 없지만 사람이 읽을 수 있는 내용
    report.fmt = fmt
    report.add("형식", f"{fmt or '알 수 없음'} ({len(data)} 바이트)")
    if fmt == "글자 파일":
        report.add("내용", preview(data.strip(), 80))

    if not report.scan(data, "파일 본문"):
        report.try_decode(data, "파일 본문")

    embedded = find_embedded(data)
    if embedded:
        report.add("숨은 파일", _shorten([f"{off:#x} {name}" for off, name in embedded]))

    if inspect_zip and ((fmt or "").startswith("ZIP") or any(name == "ZIP" for _, name in embedded)):
        _check_zip(path, report)
    if data[:3] == b"\xff\xd8\xff" or data[:2] in (b"II", b"MM"):
        _check_exif(data, report)
    if data[:4] == b"\x7fELF" or data[:2] == b"MZ":
        _check_binary(data, report)
    if use_external:
        _check_external(path, data, report)
    return report


def _run(args):
    report = analyze(args.file, compile_pattern(args.flag), use_external=not args.no_external)
    found = bool(report.flags)
    if not found:
        report.add("다음", " / ".join(next_steps(report.fmt)))

    if args.json:
        print(report.to_json())
        return 0 if found else 1

    if found:
        # 답만: --quiet 면 플래그만 한 줄씩
        for flag, where in report.flags:
            print(flag if is_quiet() else f"플래그: {flag}  [{where}]")
        if is_quiet():
            return 0
    else:
        log("[-] 플래그를 찾지 못했습니다. 아래 요약과 '다음' 줄을 참고하세요.")

    for line in report.lines:
        print(line)
    if report.missing:
        log("[i] " + external.install_hint(report.missing))
    # 종료 코드로도 알린다: 0 플래그 찾음 / 1 못 찾음 (요약은 두 경우 모두 출력한다)
    return 0 if found else 1
