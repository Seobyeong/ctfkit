"""ctfkit start: 문제 파일을 받자마자 하는 일을 한 번에 한다.

어떤 문제든 처음 몇 분은 같은 일을 한다: 폴더를 만들고, 압축을 풀고, 파일마다 형식·문자열·숨은 파일을 보고,
무엇을 봤는지 적는다. start 는 그 과정을 한 번의 호출로 묶는다.

  1. 작업 폴더를 만든다 (workspace 와 같은 구조: 노트, 명령 기록).
  2. 원본을 files/ 에 복사한다. 원본은 건드리지 않는다.
  3. 압축 파일은 extracted/ 에 푼다. 풀린 파일 안의 압축도 --depth 단계까지 따라 들어간다.
  4. 모든 파일에 triage 분석을 돌린다 (글자 파일은 auto 로 해독도 시도한다).
  5. 결과를 요약해 화면에 보여 주고 notes.md 에 적는다.

새로 분석하는 것은 없다. unpack(안전한 압축 풀기), triage(파일 분석), workspace(작업 폴더)를 조합한다.
"""

import os
import shutil

from ctfkit import external, settings, unpack
from ctfkit.commands import triage, workspace
from ctfkit.console import is_quiet, log
from ctfkit.registry import TransformError

DEFAULT_DEPTH = 3                        # 압축 안의 압축을 몇 단계까지 따라 들어갈지
MAX_SOURCES = 200                        # 폴더를 통째로 줬을 때 가져올 파일 수
MAX_ANALYZE_SIZE = 50 * 1024 * 1024      # 이보다 큰 파일은 분석하지 않고 목록에만 적는다
MAX_LINES = 30                           # 화면에 보여 줄 파일 줄 수 (노트에는 전부 적는다)

GUI_HINTS = {
    "start": {
        "label": "문제 시작",
        "order": 3,
        "group": "시작",
        "desc": "작업 폴더를 만들고, 압축을 풀고, 모든 파일을 분석해 노트에 적습니다.",
        "actions": {},
        "fields": {
            "target": {"label": "문제 파일 또는 폴더", "kind": "file"},
            "name": {"label": "작업 폴더 이름 (비우면 파일 이름)"},
            "root": {"label": "작업 폴더를 만들 위치", "default": os.getcwd},
            "flag": {"label": "플래그 정규식"},
            "depth": {"label": "압축 따라 들어갈 단계"},
            "no_external": {"label": "외부 도구 쓰지 않기"},
        },
    },
}


def register(subparsers):
    p = subparsers.add_parser("start", help="문제 시작: 작업 폴더 생성·압축 풀기·전체 분석을 한 번에")
    p.add_argument("target", help="문제 파일 또는 폴더")
    p.add_argument("--name", help="작업 폴더 이름 (기본: 파일 이름에서 확장자를 뗀 것)")
    p.add_argument("--root", help="작업 폴더를 만들 상위 경로 (기본: 현재 디렉터리)")
    p.add_argument("--flag", metavar="REGEX", help="플래그 정규식 (기본: DH{...} 등)")
    p.add_argument("--depth", type=int, default=DEFAULT_DEPTH,
                   help=f"압축 안의 압축을 따라 들어갈 단계 수 (기본 {DEFAULT_DEPTH})")
    p.add_argument("--no-external", action="store_true",
                   help="설치된 외부 도구(binwalk, exiftool 등)를 쓰지 않고 내장 분석만")
    p.set_defaults(func=_run)


# ---------------------------------------------------------------- 준비: 작업 폴더와 원본 복사

def _default_name(target: str) -> str:
    base = os.path.basename(os.path.normpath(target))
    # chall.tar.gz -> chall
    for ext in (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz"):
        if base.lower().endswith(ext):
            return base[:-len(ext)] or base
    return os.path.splitext(base)[0] or base


def _sources(target: str) -> list[tuple[str, str]]:
    """가져올 파일 목록 [(원본 경로, files/ 아래에 둘 상대 경로)]."""
    if os.path.isfile(target):
        return [(target, os.path.basename(target))]
    if not os.path.isdir(target):
        raise TransformError(f"파일이나 폴더가 아닙니다: {target}")
    found = []
    for folder, dirs, files in os.walk(target):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(folder, name)
            found.append((path, os.path.relpath(path, target)))
    if not found:
        raise TransformError(f"폴더가 비어 있습니다: {target}")
    if len(found) > MAX_SOURCES:
        raise TransformError(f"파일이 너무 많습니다 ({len(found)}개, 상한 {MAX_SOURCES}개). 문제 파일만 있는 폴더를 주세요")
    return found


def _make_workspace(root: str, name: str) -> str:
    path = os.path.join(root, name)
    if os.path.exists(path) and os.listdir(path):
        raise TransformError(f"이미 있는 폴더입니다: {path} (--name 으로 다른 이름을 주세요)")
    os.makedirs(os.path.join(path, "files"), exist_ok=True)
    open(os.path.join(path, workspace._MARKER), "w").close()
    with open(os.path.join(path, workspace._NOTES), "w", encoding="utf-8") as f:
        f.write(workspace._NOTE_TEMPLATE.format(name=name, now=workspace._now()))
    open(os.path.join(path, workspace._LOG), "a", encoding="utf-8").close()
    return path


# ---------------------------------------------------------------- 풀기와 분석

class Entry:
    """작업 폴더 안의 파일 하나에 대한 결과."""

    def __init__(self, rel: str):
        self.rel = rel            # 작업 폴더 기준 상대 경로 ('/' 구분)
        self.summary = ""         # 한 줄 요약
        self.tips = []            # 다음에 해 볼 명령


def _rel(path: str, base: str) -> str:
    return os.path.relpath(path, base).replace(os.sep, "/")


def _extract_dir(ws: str, archive: str) -> str:
    """압축 파일을 풀 폴더. 원본(files/x.zip)은 extracted/x.zip/ 에, 풀린 파일 안의 압축은 바로 옆의 이름.d/ 에 푼다."""
    files_root = os.path.join(ws, "files")
    if os.path.commonpath([os.path.realpath(files_root), os.path.realpath(archive)]) == os.path.realpath(files_root):
        return os.path.join(ws, "extracted", os.path.relpath(archive, files_root))
    return archive + ".d"


def _walk(ws: str, first: list[str], pattern, max_depth: int, use_external: bool = True):
    """파일을 하나씩 꺼내 압축이면 풀고, 아니면 분석한다.

    (결과 목록, 플래그 목록, 푼 압축 수, 쓸모 있었을 텐데 없는 외부 도구 목록)을 돌려준다.
    """
    entries, flags, unpacked, missing = [], [], 0, []
    queue = [(path, 0) for path in first]
    while queue:
        path, depth = queue.pop(0)
        entry = Entry(_rel(path, ws))
        entries.append(entry)
        size = os.path.getsize(path)

        archive = unpack.kind(path)
        if archive and depth < max_depth:
            dest = _extract_dir(ws, path)
            result = unpack.extract(path, dest)
            unpacked += 1
            entry.summary = f"{archive} 압축 → {len(result.files)}개 풂"
            if result.skipped:
                entry.summary += f", {len(result.skipped)}개 건너뜀 ({result.skipped[0]})"
            queue += [(child, depth + 1) for child in sorted(result.files)]
            continue
        if archive:
            entry.summary = f"{archive} 압축 (단계 상한 {max_depth} 에 걸려 풀지 않음. --depth 를 늘리세요)"
            continue
        if size > MAX_ANALYZE_SIZE:
            entry.summary = f"{size} 바이트 (너무 커서 분석하지 않음)"
            entry.tips = [f"forensic strings {entry.rel} --grep <정규식>"]
            continue

        report = triage.analyze(path, pattern, use_external=use_external)
        missing += [name for name in report.missing if name not in missing]
        for flag, where in report.flags:
            if all(flag != seen for seen, _ in flags):
                flags.append((flag, f"{entry.rel} · {where}"))
        entry.summary = " | ".join(f"{key} {value}" if key != "형식" else value for key, value in report.items)
        if not report.flags:
            entry.tips = triage.next_steps(report.fmt, entry.rel)
    return entries, flags, unpacked, missing


# ---------------------------------------------------------------- 출력과 노트

def _next_lines(entries: list) -> list[str]:
    """다음에 해 볼 명령. 형식별 제안을 모으되, 어디에나 붙는 strings 검색은 맨 뒤에 한 번만 둔다."""
    specific, generic = [], []
    for entry in entries:
        for tip in entry.tips:
            (generic if tip.startswith("forensic strings") else specific).append(tip)
    out = list(dict.fromkeys(specific))[:6]
    if generic:
        out.append(generic[0] if len(generic) == 1 else "forensic strings <파일> --grep <정규식>")
    return out


def _write_notes(ws: str, target: str, entries, flags, tips, missing=()) -> str:
    notes = os.path.join(ws, workspace._NOTES)
    lines = [
        f"## 자동 분석 (ctfkit start, {workspace._now()})",
        "",
        f"- 원본: `{os.path.abspath(target)}`",
        f"- 파일 {len(entries)}개",
    ]
    if missing:
        # 무엇을 확인하지 못했는지 노트만 보고도 알 수 있게 한다
        lines.append(f"- 설치되지 않아 돌리지 못한 도구: {', '.join(missing)}")
    lines.append("")
    if flags:
        lines += ["### 찾은 플래그", ""] + [f"- `{flag}` — {where}" for flag, where in flags] + [""]
    lines += ["### 파일", "", "| 경로 | 요약 |", "| --- | --- |"]
    lines += [f"| `{e.rel}` | {e.summary.replace('|', '/')} |" for e in entries]
    lines.append("")
    if tips:
        lines += ["### 다음에 해 볼 명령", ""] + [f"- `ctfkit {tip}`" for tip in tips] + [""]
    with open(notes, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return notes


def _run(args):
    if args.depth < 0:
        raise TransformError("--depth 는 0 이상이어야 합니다")
    root = args.root or os.getcwd()
    settings.set_base(root)   # 대회 설정은 작업 폴더를 만들 곳의 위에서 찾는다
    pattern = triage.compile_pattern(args.flag)
    sources = _sources(args.target)
    ws = _make_workspace(root, args.name or _default_name(args.target))

    copied = []
    for src, rel in sources:
        dest = os.path.join(ws, "files", rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(src, dest)
        copied.append(dest)

    entries, flags, unpacked, missing = _walk(ws, copied, pattern, args.depth, not args.no_external)
    tips = [] if flags else _next_lines(entries)
    notes = _write_notes(ws, args.target, entries, flags, tips, missing)
    with open(os.path.join(ws, workspace._LOG), "a", encoding="utf-8") as f:
        f.write(f"[{workspace._now()}] ctfkit start {args.target}\n")

    found = bool(flags)
    if is_quiet() and found:
        for flag, _ in flags:
            print(flag)
        return 0

    for flag, where in flags:
        print(f"플래그: {flag}  [{where}]")
    if not found:
        log("[-] 플래그를 찾지 못했습니다. 아래 요약과 '다음' 줄을 참고하세요.")
    print(f"작업 폴더: {ws}")
    print(f"파일 {len(entries)}개" + (f" (압축 {unpacked}개 풂)" if unpacked else ""))
    for entry in entries[:MAX_LINES]:
        print(f"  {entry.rel}: {entry.summary}")
    if len(entries) > MAX_LINES:
        print(f"  ... 외 {len(entries) - MAX_LINES}개 (전체는 노트 참고)")
    for tip in tips:
        print(f"다음: {tip}")
    print(f"노트: {notes}")
    if missing:
        log("[i] " + external.install_hint(missing))
    return 0 if found else 1
