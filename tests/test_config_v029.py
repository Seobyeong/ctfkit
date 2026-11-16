"""v0.29 대회별 설정: settings(찾기·읽기·쓰기), config 명령, 각 명령에 적용되는지.

Gate: 설정한 플래그 형식이 auto·triage·start·그래픽 화면에 모두 적용되고, 설정 파일이 없을 때는 v0.28 과 같다.
"""

import base64
import io
import json
import os
import zipfile

import pytest

from ctfkit import console, settings
from ctfkit.cli import main
from ctfkit.commands import template, web
from ctfkit.flags import DEFAULT_FLAG_PATTERN, FLAG_PREFIXES, compile_flag_pattern, flag_prefixes

CUSTOM = r"abc\{[^}]+\}"
CUSTOM_FLAG = "abc{custom_format_flag}"


@pytest.fixture(autouse=True)
def _reset_quiet():
    console.QUIET = False
    yield
    console.QUIET = False


@pytest.fixture
def contest(tmp_path, monkeypatch):
    """설정 파일을 찾는 대회 폴더. 현재 폴더를 여기로 옮긴다."""
    folder = tmp_path / "contest"
    folder.mkdir()
    monkeypatch.delenv("CTFKIT_CONFIG", raising=False)
    monkeypatch.chdir(folder)
    settings.reset()
    return folder


def _write_config(folder, **data):
    (folder / settings.FILENAME).write_text(json.dumps(data), encoding="utf-8")
    settings.reset()


def _run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    settings.reset()   # 명령 하나 = 프로세스 하나처럼
    return code, cap.out, cap.err


# --------------------------------------------------------------- 설정이 없을 때 (v0.28 과 같음)

def test_without_config_defaults_are_unchanged(contest):
    assert settings.current().path is None
    assert compile_flag_pattern().pattern == DEFAULT_FLAG_PATTERN.encode()
    assert flag_prefixes() == FLAG_PREFIXES
    assert web.allowed_hosts() == (set(web._DEFAULT_HOSTS), set(web._DEFAULT_SUFFIXES))


# --------------------------------------------------------------- config 명령

def test_config_set_and_show(contest, capsys):
    code, out, err = _run(capsys, "config", "set", "flag", CUSTOM)
    assert code == 0
    saved = json.loads((contest / settings.FILENAME).read_text(encoding="utf-8"))
    assert saved == {"flag": CUSTOM}
    assert "저장" in err

    code, out, _ = _run(capsys, "config", "show")
    assert f"flag:  {CUSTOM}" in out and str(contest / settings.FILENAME) in out


def test_config_allow_add_remove_unset(contest, capsys):
    assert _run(capsys, "config", "add", "allow", ".ctf.example.com")[0] == 0
    assert _run(capsys, "config", "add", "allow", "Chall.Example.org")[0] == 0
    assert _run(capsys, "config", "add", "allow", ".ctf.example.com")[0] == 0   # 같은 값은 한 번만
    assert settings.current().allow == [".ctf.example.com", "chall.example.org"]

    assert _run(capsys, "config", "remove", "allow", "chall.example.org")[0] == 0
    assert settings.current().allow == [".ctf.example.com"]
    assert _run(capsys, "config", "remove", "allow", "nope.example.org")[0] == 2

    assert _run(capsys, "config", "set", "allow", "a.example.com, .b.example.com")[0] == 0
    assert settings.current().allow == ["a.example.com", ".b.example.com"]
    assert _run(capsys, "config", "unset", "allow")[0] == 0
    assert settings.current().allow == []


@pytest.mark.parametrize("argv", [
    ("set", "flag", "abc{("),                     # 깨진 정규식
    ("add", "allow", ".com"),                     # 너무 넓은 접미사
    ("add", "allow", "http://x.example.com/"),    # 주소가 아니라 호스트만
    ("add", "allow", "*"),
])
def test_config_rejects_bad_values(contest, capsys, argv):
    code, _, err = _run(capsys, "config", *argv)
    assert code == 2 and "오류" in err
    assert not (contest / settings.FILENAME).exists()


def test_broken_config_file_is_an_error_not_a_crash(contest, capsys):
    (contest / settings.FILENAME).write_text("{not json", encoding="utf-8")
    code, _, err = _run(capsys, "auto", "aGVsbG8=")
    assert code == 2 and settings.FILENAME in err


def test_config_found_in_parent_folder(contest, capsys):
    _write_config(contest, flag=CUSTOM)
    deep = contest / "web" / "chall1"
    deep.mkdir(parents=True)
    os.chdir(deep)
    assert settings.current().path == str(contest / settings.FILENAME)


def test_explicit_config_path_from_env(contest, tmp_path, monkeypatch):
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"flag": CUSTOM}), encoding="utf-8")
    monkeypatch.setenv("CTFKIT_CONFIG", str(other))
    settings.reset()
    assert settings.current().flag == CUSTOM


# --------------------------------------------------------------- 각 명령에 적용 (Gate)

def test_auto_uses_configured_flag(contest, capsys):
    data = base64.b64encode(CUSTOM_FLAG.encode()).decode()
    code, out, _ = _run(capsys, "-q", "auto", data)
    assert code == 1   # 기본 형식에는 abc{...} 가 없다 (후보로만 보여 주고 플래그로 보지 않는다)

    _write_config(contest, flag=CUSTOM)
    code, out, _ = _run(capsys, "-q", "auto", data)
    assert code == 0 and out.strip() == CUSTOM_FLAG


def test_explicit_flag_option_beats_config(contest, capsys):
    _write_config(contest, flag=CUSTOM)
    code, out, _ = _run(capsys, "-q", "auto", base64.b64encode(b"zzz{other}").decode(), "--flag", r"zzz\{.*?\}")
    assert code == 0 and out.strip() == "zzz{other}"


def test_triage_uses_configured_flag(contest, capsys):
    path = contest / "blob.bin"
    path.write_bytes(b"\x00\x01junk" + CUSTOM_FLAG.encode() + b"\x00")
    assert _run(capsys, "triage", str(path))[0] == 1
    _write_config(contest, flag=CUSTOM)
    code, out, _ = _run(capsys, "-q", "triage", str(path))
    assert code == 0 and out.strip() == CUSTOM_FLAG


def test_start_reads_config_above_root(tmp_path, contest, capsys):
    # 다른 폴더에서 --root 로 대회 폴더를 가리켜도 대회 설정을 따른다
    _write_config(contest, flag=CUSTOM)
    elsewhere = tmp_path / "downloads"
    elsewhere.mkdir()
    chall = elsewhere / "chall.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("msg.txt", base64.b64encode(CUSTOM_FLAG.encode()))
    chall.write_bytes(buf.getvalue())
    os.chdir(elsewhere)
    code, out, _ = _run(capsys, "-q", "start", str(chall), "--root", str(contest))
    assert code == 0 and out.strip() == CUSTOM_FLAG


def test_gui_highlight_uses_configured_flag(contest):
    pytest.importorskip("tkinter")
    from ctfkit.gui import app

    assert not app._default_flag_re().search(CUSTOM_FLAG)
    _write_config(contest, flag=CUSTOM)
    assert app._default_flag_re().search(CUSTOM_FLAG)


def test_forensic_crack_template_follow_config(contest, capsys):
    _write_config(contest, flag=CUSTOM)
    path = contest / "x.bin"
    path.write_bytes(b"\xff" + CUSTOM_FLAG.encode())
    code, out, _ = _run(capsys, "forensic", "meta", str(path))
    assert CUSTOM_FLAG in out

    _write_config(contest, flag=CUSTOM)
    assert flag_prefixes()[0] == "abc"   # XOR 알려진 평문·레일 펜스 순위에 쓰인다
    assert f"FLAG = re.compile({CUSTOM!r}" in template.render_web("http://localhost/")


def test_web_allow_from_config(contest, capsys):
    url = "http://chall.ctf.example.com:31337/"
    assert not web.is_allowed(url)
    assert _run(capsys, "config", "add", "allow", ".ctf.example.com")[0] == 0
    assert web.is_allowed(url)
    assert not web.is_allowed("http://ctf.example.com.evil.net/")


# --------------------------------------------------------------- 문제 파일 속 설정 파일은 쓰지 않는다

def test_config_inside_workspace_is_ignored(contest, capsys):
    _write_config(contest, flag=CUSTOM)
    # 출제자가 압축 안에 .ctfkit.json 을 넣어 허용 호스트를 넓히려는 경우
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("dist/.ctfkit.json", json.dumps({"allow": [".evil.net"], "flag": "x"}))
        z.writestr("dist/readme.txt", "hello")
    chall = contest / "chall.zip"
    chall.write_bytes(buf.getvalue())
    assert _run(capsys, "start", str(chall))[0] == 1

    planted = contest / "chall" / "extracted" / "chall.zip" / "dist"
    assert (planted / settings.FILENAME).exists()
    os.chdir(planted)
    current = settings.current()
    assert current.path == str(contest / settings.FILENAME)
    assert current.allow == [] and current.flag == CUSTOM
    assert str(planted / settings.FILENAME) in current.ignored
    assert not web.is_allowed("http://x.evil.net/")

    code, out, err = _run(capsys, "config", "show")
    assert "쓰지 않습니다" in err


def test_config_set_inside_workspace_writes_to_contest_folder(contest, capsys):
    assert _run(capsys, "workspace", "new", "pwn1")[0] == 0
    os.chdir(contest / "pwn1")
    assert _run(capsys, "config", "set", "flag", CUSTOM)[0] == 0
    assert (contest / settings.FILENAME).exists()
    assert not (contest / "pwn1" / settings.FILENAME).exists()
    assert settings.current().flag == CUSTOM
