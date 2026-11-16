"""대회별 설정 읽기·쓰기. 설정 파일은 대회 폴더에 하나: `.ctfkit.json`.

    {"flag": "picoCTF\\{.*?\\}", "allow": [".ctf.example.com"]}

- flag: 플래그 정규식. --flag 를 주지 않았을 때 auto·triage·start·forensic·crack·그래픽 화면이 이 형식을 쓴다.
- allow: web 이 요청해도 되는 호스트를 기본(localhost, *.dreamhack.games)에 **더한다.** '.' 로 시작하면 접미사.

찾는 법: 기준 폴더(보통 현재 폴더)에서 위로 올라가며 처음 만나는 `.ctfkit.json`.
단, **작업 폴더(ctfkit workspace·start 가 만든 폴더) 안에 있는 설정 파일은 쓰지 않는다.** 작업 폴더에는 문제 파일을
풀어 놓으므로, 출제자가 넣은 `.ctfkit.json` 이 허용 호스트를 넓히는 일을 막기 위해서다. 허용 호스트는 사용자가
직접 적은 것만 따른다 (ROADMAP v0.29). 설정 파일이 없으면 v0.28 과 똑같이 동작한다.

CTFKIT_CONFIG 환경 변수: 파일 경로를 주면 그 파일만 쓰고, `none` 이면 설정 파일을 찾지 않는다 (테스트·벤치마크용).
"""

import json
import os
import re
from dataclasses import dataclass, field

from ctfkit.registry import TransformError

FILENAME = ".ctfkit.json"
WORKSPACE_MARKER = ".ctfkit-workspace"   # commands/workspace.py 의 _MARKER 와 같은 값
KEYS = ("flag", "allow")
# 허용 호스트 한 항목: 이름 또는 '.' 로 시작하는 접미사. 접미사는 점이 둘 이상이어야 한다 ('.com' 처럼 넓은 것 거부)
_HOST = re.compile(r"(?:[a-z0-9-]+\.)*[a-z0-9-]+")


@dataclass
class Settings:
    path: str | None = None                     # 읽은 파일 (없으면 None)
    flag: str | None = None
    allow: list[str] = field(default_factory=list)
    ignored: list[str] = field(default_factory=list)   # 작업 폴더 안이라 쓰지 않은 설정 파일


_base: str | None = None        # 찾기 시작할 폴더 (None 이면 현재 폴더)
_cache: Settings | None = None


def set_base(path: str | None) -> None:
    """설정을 찾기 시작할 폴더를 바꾼다. start --root 처럼 현재 폴더가 아닌 곳에 작업할 때 쓴다."""
    global _base, _cache
    _base, _cache = path, None


def reset() -> None:
    set_base(None)


def check_flag(pattern: str) -> str:
    try:
        re.compile(pattern.encode())
    except re.error as e:
        raise TransformError(f"잘못된 플래그 정규식: {pattern} ({e})") from e
    if not pattern:
        raise TransformError("플래그 정규식이 비어 있습니다")
    return pattern


def check_host(item: str) -> str:
    item = item.strip().lower()
    body = item[1:] if item.startswith(".") else item
    if not _HOST.fullmatch(body):
        raise TransformError(f"호스트 형식이 아닙니다: {item!r} (예: host.example.com, .ctf.example.com)")
    if item.startswith(".") and body.count(".") < 1:
        raise TransformError(f"너무 넓은 접미사입니다: {item} (예: .ctf.example.com)")
    return item


def _workspace_root(start: str) -> str | None:
    """start 를 품은 가장 가까운 작업 폴더."""
    folder = os.path.abspath(start)
    while True:
        if os.path.isfile(os.path.join(folder, WORKSPACE_MARKER)):
            return folder
        parent = os.path.dirname(folder)
        if parent == folder:
            return None
        folder = parent


def find(start: str | None = None) -> tuple[str | None, list[str]]:
    """(쓸 설정 파일, 작업 폴더 안에 있어 쓰지 않은 설정 파일들)."""
    folder = os.path.abspath(start or os.getcwd())
    ws = _workspace_root(folder)
    ignored = []
    while True:
        candidate = os.path.join(folder, FILENAME)
        if os.path.isfile(candidate):
            inside = ws is not None and os.path.commonpath([ws, folder]) == ws
            if not inside:
                return candidate, ignored
            ignored.append(candidate)
        parent = os.path.dirname(folder)
        if parent == folder:
            return None, ignored
        folder = parent


def load_file(path: str) -> Settings:
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError) as e:
        raise TransformError(f"설정 파일을 읽을 수 없습니다: {path} ({e})") from e
    if not isinstance(raw, dict):
        raise TransformError(f"설정 파일은 JSON 객체여야 합니다: {path}")
    settings = Settings(path=path)
    flag = raw.get("flag")
    if flag is not None:
        if not isinstance(flag, str):
            raise TransformError(f"{path}: flag 는 문자열이어야 합니다")
        settings.flag = check_flag(flag)
    allow = raw.get("allow", [])
    if not isinstance(allow, list) or not all(isinstance(x, str) for x in allow):
        raise TransformError(f"{path}: allow 는 문자열 목록이어야 합니다")
    settings.allow = [check_host(x) for x in allow]
    return settings


def current() -> Settings:
    """지금 쓸 설정. 한 번 읽으면 프로세스 안에서 다시 읽지 않는다."""
    global _cache
    if _cache is None:
        env = os.environ.get("CTFKIT_CONFIG", "").strip()
        if env.lower() == "none":
            _cache = Settings()
        elif env:
            _cache = load_file(env)
        else:
            path, ignored = find(_base)
            _cache = load_file(path) if path else Settings()
            _cache.ignored = ignored
    return _cache


# ---------------------------------------------------------------- 쓰기 (ctfkit config)

def write_target(start: str | None = None) -> str:
    """config set 이 쓸 파일. 이미 쓰고 있는 설정 파일, 없으면 대회 폴더(작업 폴더 안이면 그 바로 위, 아니면 현재 폴더)."""
    path, _ = find(start)
    if path:
        return path
    folder = os.path.abspath(start or os.getcwd())
    ws = _workspace_root(folder)
    return os.path.join(os.path.dirname(ws) if ws else folder, FILENAME)


def save(path: str, data: dict) -> None:
    data = {key: data[key] for key in KEYS if data.get(key) not in (None, [])}
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    global _cache
    _cache = None   # 다음 current() 가 새 내용을 읽게


def read_raw(path: str) -> dict:
    if not os.path.isfile(path):
        return {}
    s = load_file(path)
    return {"flag": s.flag, "allow": list(s.allow)}
