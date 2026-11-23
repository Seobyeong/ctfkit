"""ctfkit start: 문제 파일을 받자마자 하는 일을 한 번에 한다.

어떤 문제든 처음 몇 분은 같은 일을 한다: 폴더를 만들고, 압축을 풀고, 파일마다 형식·문자열·숨은 파일을 보고,
무엇을 봤는지 적는다. start 는 그 과정을 한 번의 호출로 묶는다.

  1. 작업 폴더를 만든다 (workspace 와 같은 구조: 노트, 명령 기록).
  2. 원본을 files/ 에 복사한다. 원본은 건드리지 않는다.
  3. 압축 파일은 extracted/ 에 푼다. 풀린 파일 안의 압축도 --depth 단계까지 따라 들어간다.
  4. 모든 파일에 triage 분석을 돌린다 (글자 파일은 auto 로 해독도 시도한다).
  5. 결과를 요약해 화면에 보여 주고 notes.md 에 적는다.
  6. AI 에이전트가 읽을 요약을 AGENTS.md 에 적는다 (CLAUDE.md 는 그것을 불러온다): 소스에서 성립하지 않는 공격,
     값 파일(values.json), 값으로 직접 시도한 공격, 줄인 소스(ai/). 사람이 읽을 필요는 없다.

새로 분석하는 것은 없다. unpack(안전한 압축 풀기), triage(파일 분석), workspace(작업 폴더)를 조합한다.
"""

import hashlib
import locale
import os
import re
import shutil

from ctfkit import brief, external, settings, unpack
from ctfkit.commands import triage, workspace
from ctfkit.console import is_quiet, log
from ctfkit.registry import TransformError

DEFAULT_DEPTH = 5                        # 압축 안의 압축을 몇 단계까지 (zip → tar.gz → tar → rootfs.cpio.gz → cpio 도 흔하다)
MAX_SOURCES = 200                        # 폴더를 통째로 줬을 때 가져올 파일 수
MAX_ANALYZE_SIZE = 50 * 1024 * 1024      # 이보다 큰 파일은 분석하지 않고 목록에만 적는다
MAX_LINES = 30                           # 화면에 보여 줄 파일 줄 수 (노트에는 전부 적는다)
# 압축 항목 하나의 상한. 디스크 이미지·펌웨어(수십 MB)는 흔하므로 unpack 의 기본(50MB)보다 크게 잡는다.
# 압축 폭탄은 압축 파일 하나의 전체 상한이 막는다
START_LIMITS = unpack.Limits(max_file_size=256 * 1024 * 1024, max_total_size=512 * 1024 * 1024)
# 윈도우는 경로가 260자를 넘으면 파일을 열지 못한다. 압축 안 항목의 경로가 이보다 길어지면 짧은 폴더(x/<해시>)에 푼다
LONG_PATH = 240

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
    name = None
    # chall.tar.gz -> chall
    for ext in (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz"):
        if base.lower().endswith(ext):
            name = base[:-len(ext)] or base
            break
    name = name or os.path.splitext(base)[0] or base
    # 같은 파일을 두 번 받으면 브라우저가 붙이는 " (1)" 은 뗀다 (이미 있는 폴더와는 _make_workspace 가 겹치지 않게 한다)
    return re.sub(r" \(\d+\)$", "", name) or name


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


def _free_name(root: str, name: str) -> str:
    """기본 이름이 이미 쓰이고 있으면 name-2, name-3 ... 중 빈 것. --name 으로 직접 준 이름에는 쓰지 않는다."""
    candidate, n = name, 1
    while os.path.exists(os.path.join(root, candidate)) and n < 100:
        n += 1
        candidate = f"{name}-{n}"
    return candidate


def _make_workspace(root: str, name: str) -> str:
    path = os.path.join(root, name)
    if os.path.exists(path) and not os.path.isdir(path):
        # 문제 파일 chall 과 chall.zip 을 같은 폴더에 받으면 기본 이름(chall)이 파일과 겹친다
        raise TransformError(f"같은 이름의 파일이 있어 작업 폴더를 만들 수 없습니다: {path} (--name 으로 다른 이름을 주세요)")
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
        self.recovered = False    # 모양을 바꿔 숨긴 것을 ctfkit 이 되살린 파일인가 (사람이 열어 봐야 한다)
        self.path = ""            # 실제 경로
        self.report = None        # triage 결과 (분석한 파일만)
        self.role = None          # "환경" (QEMU·커널 이미지 등, 분석 대상 아님) / "빌드" (Dockerfile·설정) / None
        self.key = False          # 출제자가 바꾼 것을 담은 파일인가 (패치)
        self.detail = ""          # 요약 뒤에 자르지 않고 붙이는 말 (rootfs 의 시작 스크립트 목록 등)


# 문제를 돌리기 위한 실행 환경. 공격 대상이 아니므로 분석·제안을 하지 않는다 (커널·VM 문제에서 qemu 를 pwn 대상으로 권하던 문제)
_ENVIRONMENT = [
    (re.compile(r"qemu(-system)?-[\w.+-]*", re.I), "QEMU 에뮬레이터"),
    (re.compile(r"(qemu|ovmf)[\w.+-]*\.(apk|deb|rpm)", re.I), "QEMU 패키지"),
    (re.compile(r"(qemu_efi|ovmf)[\w.-]*|[\w.-]*\.fd", re.I), "펌웨어 (UEFI)"),
    (re.compile(r"(b?zImage|u?Image|vmlinuz[\w.-]*)(\.gz)?"), "커널 이미지"),
]
# 문제를 만들거나 띄우는 파일. 값(values.json)을 모으지 않고 명령을 제안하지 않는다
_BUILD = re.compile(r"Dockerfile|docker-compose[\w.-]*|Makefile|\.PKGINFO|[\w.-]*\.config|\.config|mdev\.conf|"
                    r"build[\w-]*\.sh|xinetd[\w.-]*|[\w.-]*\.(apk|deb|rpm)", re.I)
_PATCH = re.compile(r"[\w.-]*\.(patch|diff)", re.I)


def classify(path: str) -> tuple[str | None, str | None]:
    """(역할, 설명). 이름만 본다. 확실한 이름(qemu-system-*, Image, Dockerfile ...)이 아니면 (None, None)."""
    name = os.path.basename(path)
    for pattern, label in _ENVIRONMENT:
        if pattern.fullmatch(name):
            return "환경", label
    if _BUILD.fullmatch(name):
        return "빌드", "빌드·배포 설정"
    return None, None


def _is_patch(path: str) -> bool:
    if _PATCH.fullmatch(os.path.basename(path)):
        return True
    try:
        with open(path, "rb") as f:
            head = f.read(64)
    except OSError:
        return False
    return head.startswith((b"diff --git ", b"--- a/", b"Index: "))


# 루트 파일 시스템(cpio)에서 배포판이 깔아 둔 경로. 파일이 수백 개라 하나씩 분석하면 요약이 묻힌다
_SYSTEM_DIRS = {"bin", "sbin", "usr", "lib", "lib32", "lib64", "etc", "var", "dev", "proc", "sys", "run", "tmp", "linuxrc"}
_IN_TREE_MODULE = re.compile(r"lib/modules/[^/]+/kernel/.+\.ko(\.[gx]z)?")


def _split_rootfs(dest: str, files: list[str]) -> tuple[list[str], str]:
    """cpio 로 푼 파일을 (분석할 것, 요약에 덧붙일 말) 로 나눈다.

    배포판 경로(lib·usr·bin·etc ...)는 세기만 하고, 그 밖(/root, /home, /init, /flag, /opt ...)과 커널 트리 밖의 모듈(.ko)만 분석한다.
    시작 스크립트(etc/init.d)는 이름만 적는다. 출제자가 넣은 서비스가 여기서 드러난다 (S98xxx 같은 이름).
    """
    keep, system, modules, scripts = [], 0, 0, []
    for path in files:
        rel = os.path.relpath(path, dest).replace(os.sep, "/")
        top = rel.split("/", 1)[0]
        if rel.startswith("etc/init.d/"):
            scripts.append(rel[len("etc/init.d/"):])
        elif _IN_TREE_MODULE.fullmatch(rel):
            modules += 1
        elif rel.endswith((".ko", ".ko.gz", ".ko.xz")) or top not in _SYSTEM_DIRS:
            keep.append(path)
            continue
        system += 1
    note = f"배포판 경로(lib·usr·bin·etc 등) {system}개는 분석하지 않음"
    if modules:
        note += f" (커널 트리 안의 모듈 {modules}개 포함)"
    if scripts:
        note += f". 시작 스크립트 etc/init.d: {', '.join(sorted(scripts))}"
    return keep, note


def _digest(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _rel(path: str, base: str) -> str:
    return os.path.relpath(path, base).replace(os.sep, "/")


def _extract_dir(ws: str, archive: str) -> str:
    """압축 파일을 풀 폴더. 원본(files/x.zip)은 extracted/x.zip/ 에, 풀린 파일 안의 압축은 바로 옆의 이름.d/ 에 푼다.
    윈도우에서 풀린 항목의 경로가 260자 제한에 걸릴 만큼 길면(중첩 압축 + 긴 이름) x/<해시 8자리>/ 에 푼다."""
    files_root = os.path.join(ws, "files")
    if os.path.commonpath([os.path.realpath(files_root), os.path.realpath(archive)]) == os.path.realpath(files_root):
        dest = os.path.join(ws, "extracted", os.path.relpath(archive, files_root))
    else:
        dest = archive + ".d"
    if os.name == "nt" and len(os.path.abspath(dest)) + 1 + unpack.longest_name(archive) > LONG_PATH:
        dest = os.path.join(ws, "x", hashlib.sha256(_rel(archive, ws).encode()).hexdigest()[:8])
    return dest


def _recovered_path(ws: str, path: str, ext: str) -> str:
    """되살린 파일을 둘 곳. files/ 의 원본이면 extracted/ 아래에, 아니면 바로 옆에 이름.recovered.확장자 로 둔다."""
    files_root = os.path.realpath(os.path.join(ws, "files"))
    real = os.path.realpath(path)
    if os.path.commonpath([files_root, real]) == files_root:
        path = os.path.join(ws, "extracted", os.path.relpath(real, files_root))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path + ".recovered" + ext


def _walk(ws: str, first: list[str], pattern, max_depth: int, use_external: bool = True, evidence=None):
    """파일을 하나씩 꺼내 압축이면 풀고, 아니면 분석한다.

    (결과 목록, 플래그 목록, 푼 압축 수, 쓸모 있었을 텐데 없는 외부 도구 목록)을 돌려준다.
    """
    entries, flags, unpacked, missing = [], [], 0, []
    queue = [(path, 0) for path in first]
    recovered = set()
    seen = {}   # 내용 해시 → 먼저 본 파일의 상대 경로
    while queue:
        path, depth = queue.pop(0)
        entry = Entry(_rel(path, ws))
        entry.recovered = path in recovered
        entry.path = path
        entries.append(entry)
        size = os.path.getsize(path)

        # 같은 내용은 한 번만 본다 (문제 압축 안에 다른 압축이 통째로 들어 있는 경우 등)
        digest = _digest(path)
        if digest in seen:
            entry.role = "중복"
            entry.summary = f"{seen[digest]} 와 내용이 같음 (다시 분석하지 않음)"
            continue
        seen[digest] = entry.rel

        role, label = classify(path)
        if role == "환경":
            entry.role = role
            entry.summary = f"{label} ({size} 바이트). 문제를 돌리는 환경이라 분석하지 않음"
            continue

        archive = unpack.kind(path)
        if archive and depth < max_depth:
            dest = _extract_dir(ws, path)
            result = unpack.extract(path, dest, START_LIMITS)
            unpacked += 1
            entry.summary = f"{archive} 압축 → {len(result.files)}개 풂"
            if _rel(dest, ws).startswith("x/"):
                entry.summary += f" ({_rel(dest, ws)}/)"
            skipped = [s for s in result.skipped if not s.startswith("(링크 ")]   # 링크는 건너뛴 게 아니라 원래 풀지 않는다
            if skipped:
                entry.summary += f", {len(skipped)}개 건너뜀 ({skipped[0]})"
            children = sorted(result.files)
            if archive == "cpio":
                children, entry.detail = _split_rootfs(dest, children)
            queue += [(child, depth + 1) for child in children]
            continue
        if archive:
            entry.summary = f"{archive} 압축 (단계 상한 {max_depth} 에 걸려 풀지 않음. --depth 를 늘리세요)"
            continue
        if size > MAX_ANALYZE_SIZE:
            with open(path, "rb") as f:
                fmt = triage.identify(f.read(1 << 16))
            entry.summary = f"{fmt or '형식 모름'} ({size} 바이트, 너무 커서 분석하지 않음)"
            entry.tips = [f"forensic strings {entry.rel} --grep <정규식>"]
            continue
        entry.role = role
        entry.key = _is_patch(path)

        report = triage.analyze(path, pattern, use_external=use_external)
        entry.report = report
        missing += [name for name in report.missing if name not in missing]
        for flag, where in report.flags:
            if all(flag != seen for seen, _ in flags):
                flags.append((flag, f"{entry.rel} · {where}"))
                if evidence is not None and flag in report.evidence:
                    evidence[flag] = report.evidence[flag]
        entry.summary = " | ".join(f"{key} {value}" if key != "형식" else value for key, value in report.items)
        if report.recovered is not None and depth < max_depth:
            # 되살린 파일을 저장하고 그것도 분석한다 (풀린 압축과 같은 단계로 센다)
            out = _recovered_path(ws, path, report.recovered.ext)
            with open(out, "wb") as f:
                f.write(report.recovered.data)
            entry.summary += f" → {_rel(out, ws)}"
            recovered.add(out)
            queue.append((out, depth + 1))
        elif not report.flags and entry.role is None:
            entry.tips = triage.next_steps(report.fmt, entry.rel, report.source, report.recovered, report.brief)
    return entries, flags, unpacked, missing


# ---------------------------------------------------------------- AI 에이전트용 요약

AGENTS = "AGENTS.md"
CLAUDE = "CLAUDE.md"
VALUES = "values.json"
AI_DIR = "ai"
MAX_SUMMARY = 160      # AGENTS.md 에 적는 파일 요약 한 줄의 글자 수


class AgentBrief:
    """start 가 소스·값 파일에서 모은 것. AGENTS.md 와 화면 출력이 함께 쓴다."""

    def __init__(self):
        self.sources = []      # [(Entry, SourceBrief 또는 None, 줄인 파일 상대 경로 또는 None, Compacted)]
        self.values = {}       # 이름 → 정수
        self.origins = {}      # 이름 → "files/out.txt:3"
        self.value_files = {}  # Entry.rel → [이름]
        self.tried = []        # 값으로 직접 해 본 공격 기록
        self.plaintext = None  # 시도가 성공했으면 평문


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def _free_file(folder: str, name: str) -> str:
    base, n = name, 1
    while os.path.exists(os.path.join(folder, name)):
        n += 1
        name = f"{n}-{base}"
    return name


def _collect_brief(ws: str, entries, pattern, flags, evidence=None) -> AgentBrief:
    """소스는 줄이고, 글자 파일에서는 값을 모으고, 값이 있으면 가벼운 공격을 직접 해 본다. 찾은 플래그는 flags 에 더한다."""
    out = AgentBrief()
    e_hint = None
    hints, alphabets, texts = [], [], []
    for entry in entries:
        report = entry.report
        if report is None:
            continue
        if report.fmt is None and report.source is None:
            texts.append(entry)   # 매직이 없는 파일: 글자 파일이 아니어도(유니코드 문장 등) 다중 시저 대상일 수 있다
        if report.fmt != "글자 파일":
            continue
        text = _read_text(entry.path)
        if report.source is not None:
            hints += brief.source_numbers(text, entry.rel)
            alphabets += brief.source_alphabets(text, entry.rel)
            sb = report.brief
            if sb is not None and sb.e is not None and e_hint is None:
                e_hint = sb.e
            small = brief.compact(text, os.path.basename(entry.path))
            rel = None
            if small.elided:
                folder = os.path.join(ws, AI_DIR)
                os.makedirs(folder, exist_ok=True)
                name = _free_file(folder, os.path.basename(entry.path) + ".txt")
                with open(os.path.join(folder, name), "w", encoding="utf-8", newline="\n") as f:
                    f.write(small.text)
                rel = f"{AI_DIR}/{name}"
            out.sources.append((entry, sb, rel, small))
        elif report.recovered is None and entry.role is None and not entry.key:
            texts.append(entry)
            added = brief.merge_values(out.values, out.origins, brief.extract_values(text), entry.rel)
            if added:
                out.value_files[entry.rel] = added
                entry.tips = []   # 값은 values.json 으로 옮겼으니 이 파일에 strings 검색을 권하지 않는다
    if out.values:
        brief.write_values(os.path.join(ws, VALUES), out.values, out.origins)
        out.tried, out.plaintext = brief.try_rsa(out.values, e_hint, hints)
        if out.plaintext:
            how = out.tried[-1].split(":")[0]
            for m in pattern.finditer(out.plaintext):
                flag = m.group(0).decode("latin-1")
                if all(flag != seen for seen, _ in flags):
                    flags.append((flag, f"{VALUES} · RSA {how}"))
                    if evidence is not None:
                        evidence[flag] = f"{out.tried[-1]}, 복호한 평문 {out.plaintext[:80]!r}"
    if alphabets and not flags:
        _try_shift(texts, alphabets, pattern, flags, out, evidence)
    return out


# 바이그램 평균 로그확률: 영어 문장 약 -2.5, 맞는 키라도 고유명사·숫자가 많으면 -2.9, 무작위 키 -4.4.
# 한 자리 틀린 키(-3.2)는 점수로 가를 수 없어 언덕 오르기의 최적점에 맡기고, 여기서는 엉터리만 거른다
SHIFT_MIN_BIGRAM = -3.5


def _try_shift(texts, alphabets, pattern, flags, out: AgentBrief, evidence) -> None:
    """소스가 정한 알파벳(예: 대문자+소문자+숫자 62글자)으로 미는 다중 시저를 글자 파일에 시도한다.
    26글자 비즈네르는 auto 가 다루므로, 여기서는 소스에 알파벳이 따로 정의된 경우만 본다."""
    from ctfkit.flags import is_placeholder
    from ctfkit.ngram import bigram_score

    for entry in texts:
        try:
            with open(entry.path, encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError):
            continue
        if len(text) > 200_000:
            continue
        for where, alphabet in alphabets:
            result = brief.crack_shift(text, alphabet)
            if result is None:
                continue
            # 플래그 본문(hex 등)은 영어가 아니므로 빼고 점수를 매긴다
            english = bigram_score(pattern.sub(b" ", result.plaintext.encode("ascii", "ignore")))
            step = (f"{where} 의 {len(alphabet)}글자 알파벳으로 다중 시저, 키 길이 {len(result.key)}, "
                    f"키 {result.key}, 키 위치는 {'모든 글자' if result.mode == 'all' else '알파벳 글자'}마다 넘어감")
            found = [m.group(0) for m in pattern.finditer(result.plaintext.encode("utf-8", "ignore"))]
            found = [f.decode("latin-1") for f in found if not is_placeholder(f.decode("latin-1"))]
            if not found or english < SHIFT_MIN_BIGRAM:
                out.tried.append(f"{entry.rel}: {step} - 플래그 없음")
                continue
            out.tried.append(f"{entry.rel}: {step} - 성공")
            for flag in found:
                if all(flag != seen for seen, _ in flags):
                    flags.append((flag, f"{entry.rel} · 다중 시저 ({where})"))
                    if evidence is not None:
                        evidence[flag] = (f"{step}. 평문이 영어 문장으로 읽힘 (바이그램 {english:.2f}), "
                                          f"앞부분 {result.plaintext[:60]!r}")
            return


def agent_mode() -> bool:
    """AI 에이전트의 셸에서 실행됐는가. CTFKIT_AGENT=1/0 이 우선이고, 없으면 에이전트가 넣는 환경 변수를 본다
    (Claude Code 는 CLAUDECODE, 그 밖의 여러 에이전트는 AI_AGENT)."""
    forced = os.environ.get("CTFKIT_AGENT")
    if forced is not None:
        return forced.strip() not in ("", "0")
    return any(os.environ.get(name, "").strip() not in ("", "0") for name in ("CLAUDECODE", "AI_AGENT"))


# 에이전트가 자주 부르지만 없을 수 있는 도구와 ctfkit 의 대신할 명령
_TOOL_ALTERNATIVES = {"strings": "ctfkit forensic strings FILE", "file": "ctfkit forensic id FILE",
                      "binwalk": "ctfkit forensic carve FILE"}


def _is_store_stub(path: str | None) -> bool:
    # 윈도우의 python3 는 설치하지 않으면 Microsoft Store 안내만 띄우는 껍데기다 ("Python was not found")
    return bool(path) and "windowsapps" in path.replace("\\", "/").lower()


def environment_lines() -> list[str]:
    """에이전트가 헛걸음하기 쉬운 실행 환경만 적는다. 리눅스 + UTF-8 + 도구가 다 있으면 빈 목록 (토큰을 쓰지 않음).

    실제 문제 측정에서 에이전트는 python3 를 찾다가("Python was not found"), strings 가 없어서, 콘솔 인코딩(cp949) 오류로
    실행마다 1~1.5번 왕복을 버렸다. ctfkit 이 있든 없든 같았다.
    """
    lines = []
    py3, py = shutil.which("python3"), shutil.which("python")
    if (not py3 or _is_store_stub(py3)) and py and not _is_store_stub(py):
        lines.append("- 파이썬은 `python` 으로 실행 (`python3` 은 " + ("Microsoft Store 안내만 뜸" if py3 else "없음") + ")")
    encoding = (locale.getpreferredencoding(False) or "").lower().replace("-", "")
    # PYTHONIOENCODING 이 있어도 적는다. 에이전트는 받은 파일을 다룰 때 `python -I` 를 자주 쓰는데, -I 는 그 변수를 무시한다
    if encoding not in ("utf8", ""):
        lines.append(f"- 콘솔 인코딩이 {encoding} 이다. 한글·특수문자(–, ✓ 등)를 출력하는 스크립트는 `python -X utf8` 로 실행")
    missing = [tool for tool in _TOOL_ALTERNATIVES if not shutil.which(tool)]
    if missing:
        lines.append("- 없는 도구: " + ", ".join(f"{t} → `{_TOOL_ALTERNATIVES[t]}`" for t in missing))
    if lines and os.name == "nt":
        lines.insert(0, "- 윈도우 (셸은 Git Bash 또는 PowerShell)")
    return lines


def _write_agents(ws: str, entries, flags, tips, ab: AgentBrief, evidence=None) -> str:
    """AGENTS.md: 에이전트가 처음 한 번 읽을 요약. 사실·제외·시도·후보만 짧게 적는다."""
    lines = ["# ctfkit 요약 (AI 에이전트용, ctfkit start 가 만듦)",
             "사람용 노트는 notes.md. 줄 번호는 모두 원본 기준."]
    if flags:
        for flag, where in flags:
            lines.append(f"플래그: {flag} ({where})")
            if evidence and flag in evidence:
                lines.append(f"  근거: {evidence[flag]}")
    else:
        lines.append("플래그: 못 찾음")
    lines += ["", "## 파일"]
    shown = set()
    keys = [e for e in entries if e.key]
    for entry in keys:
        shown.add(entry.rel)
        lines.append(f"- {entry.rel}: **패치 (출제자가 바꾼 부분, 먼저 읽을 것)**")
    for role, title in (("환경", "실행 환경 (QEMU·커널 이미지 등, 분석 대상 아님)"), ("빌드", "빌드·배포 설정"),
                        ("중복", "같은 내용이라 건너뛴 파일")):
        group = [e.rel for e in entries if e.role == role]
        if group:
            shown.update(group)
            names = ", ".join(os.path.basename(r) for r in group[:8]) + (f" 외 {len(group) - 8}개" if len(group) > 8 else "")
            lines.append(f"- {title} {len(group)}개: {names}")
    for entry, sb, rel, small in ab.sources:
        shown.add(entry.rel)
        note = f"- {entry.rel}: 소스"
        if rel:
            note += (f". **{rel} 를 읽을 것** ({small.original_lines}줄 → {small.kept_lines}줄, "
                     "[Lx-Ly 생략] 부분만 원본에서 확인)")
        lines.append(note)
    for entry in entries:
        if entry.rel in shown:
            continue
        if entry.rel in ab.value_files:
            names = ", ".join(brief.describe_value(n, ab.values[n]) for n in ab.value_files[entry.rel])
            lines.append(f"- {entry.rel}: 값 {names} → {VALUES}")
            continue
        summary = entry.summary if len(entry.summary) <= MAX_SUMMARY else entry.summary[:MAX_SUMMARY] + "..."
        if entry.detail:
            summary += f". {entry.detail}"
        lines.append(f"- {entry.rel}: {summary}")
    if ab.values:
        lines += ["", f"값은 {VALUES} 에 있다. 숫자를 스크립트에 옮겨 적지 말고 읽을 것: "
                      f"`V = json.load(open('{VALUES}'))` (뼈대: `ctfkit template rsa --values {VALUES}`)"]

    facts, excluded, candidates = [], [], []
    for entry, sb, _, _ in ab.sources:
        if sb is None:
            continue
        facts += [f"- {sb.name}:{n} {text}" for n, text in sorted(sb.facts)]
        excluded += [f"- {v.attack}: {v.reason}" + (f" ({v.where(sb.name)})" if v.lines else "") for v in sb.excluded]
        candidates += [f"- {v.attack}: {v.reason}" + (f" ({v.where(sb.name)})" if v.lines else "")
                       + (f" → `ctfkit {v.tip}`" if v.tip else "") for v in sb.candidates]
    if facts:
        lines += ["", "## 소스의 사실"] + facts
    if excluded:
        lines += ["", "## 제외 (코드상 성립하지 않음, 시도하지 말 것)"] + excluded
    if ab.tried:
        lines += ["", "## ctfkit 이 이미 시도함 (값으로 직접)"] + [f"- {t}" for t in ab.tried]
        if ab.plaintext is not None and not flags:
            lines.append(f"- 평문: {ab.plaintext[:120]!r}")
    if candidates:
        lines += ["", "## 후보 (전제 조건이 코드에 보임)"] + candidates
    if tips:
        lines += ["", "## 다음 명령"] + [f"- `ctfkit {tip}`" for tip in tips]
    env = environment_lines()
    if env:
        lines += ["", "## 실행 환경"] + env
    lines += ["", "ctfkit: `ctfkit -q CMD` 는 답만 출력, 종료 코드 0 찾음 / 1 못 찾음. 명령 목록: `ctfkit guide`"]
    text = "\n".join(lines) + "\n"
    with open(os.path.join(ws, AGENTS), "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    # Claude Code 는 CLAUDE.md 를, 다른 에이전트(Codex 등)는 AGENTS.md 를 읽는다. 내용은 한 곳에만 둔다
    with open(os.path.join(ws, CLAUDE), "w", encoding="utf-8", newline="\n") as f:
        f.write(f"@{AGENTS}\n")
    return text


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
    lines += [f"| `{e.rel}` | {(e.summary + (f'. {e.detail}' if e.detail else '')).replace('|', '/')} |" for e in entries]
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
    ws = _make_workspace(root, args.name or _free_name(root, _default_name(args.target)))

    copied = []
    for src, rel in sources:
        dest = os.path.join(ws, "files", rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(src, dest)
        copied.append(dest)

    evidence = {}
    entries, flags, unpacked, missing = _walk(ws, copied, pattern, args.depth, not args.no_external, evidence)
    ab = _collect_brief(ws, entries, pattern, flags, evidence)
    tips = [] if flags else _next_lines(entries)
    if ab.values:
        tips = [tip.replace("template rsa -n N -e E -c C", f"template rsa --values {VALUES}") for tip in tips]
    notes = _write_notes(ws, args.target, entries, flags, tips, missing)
    agents_text = _write_agents(ws, entries, flags, tips, ab, evidence)
    with open(os.path.join(ws, workspace._LOG), "a", encoding="utf-8") as f:
        f.write(f"[{workspace._now()}] ctfkit start {args.target}\n")

    found = bool(flags)
    if is_quiet() and found:
        for flag, _ in flags:
            print(flag)
        return 0

    if agent_mode():
        # 에이전트는 이 출력을 읽고 곧바로 AGENTS.md 를 또 열었다 (실제 문제 측정의 모든 실행). 같은 내용을 두 번 읽고
        # 왕복을 한 번 더 쓰므로, 에이전트에게는 사람용 목록 대신 AGENTS.md 를 바로 보여 준다
        print(f"작업 폴더: {ws}")
        print(f"(에이전트 모드: 아래는 {AGENTS} 와 같은 내용이니 다시 읽지 않아도 된다. 사람용 출력은 CTFKIT_AGENT=0)")
        print(agents_text, end="")
        if missing:
            log("[i] " + external.install_hint(missing))
        return 0 if found else 1

    for flag, where in flags:
        print(f"플래그: {flag}  [{where}]")
        if flag in evidence:
            print(f"  근거: {evidence[flag]}")
    if not found:
        log("[-] 플래그를 찾지 못했습니다. 아래 요약과 '다음' 줄을 참고하세요.")
    print(f"작업 폴더: {ws}")
    print(f"파일 {len(entries)}개" + (f" (압축 {unpacked}개 풂)" if unpacked else ""))
    for entry in entries[:MAX_LINES]:
        print(f"  {entry.rel}: {entry.summary}" + (f". {entry.detail}" if entry.detail else ""))
    if len(entries) > MAX_LINES:
        print(f"  ... 외 {len(entries) - MAX_LINES}개 (전체는 노트 참고)")
    for entry, sb, _, _ in ab.sources:
        if sb is not None and sb.excluded:
            print(f"제외({entry.rel}): " + ", ".join(dict.fromkeys(v.attack for v in sb.excluded)))
    if ab.values:
        print(f"값: {', '.join(brief.describe_value(n, v) for n, v in ab.values.items())} → {VALUES}")
    for line in ab.tried:
        print(f"시도: {line}")
    for tip in tips:
        print(f"다음: {tip}")
    if not found:
        # 되살린 이미지·문서는 플래그가 그림으로 들어 있는 경우가 많다. 글자 검색으로는 찾을 수 없으니 직접 연다
        for entry in entries:
            if entry.recovered:
                print(f"열어 볼 파일: {os.path.join(ws, *entry.rel.split('/'))}")
    print(f"노트: {notes}")
    print(f"AI 요약: {os.path.join(ws, AGENTS)}")
    if missing:
        log("[i] " + external.install_hint(missing))
    return 0 if found else 1
