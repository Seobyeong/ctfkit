"""v0.26 문제 시작 자동화: 안전한 압축 풀기(unpack)와 start 명령."""

import base64
import gzip
import io
import os
import tarfile
import zipfile

import pytest

from ctfkit import console, unpack
from ctfkit.cli import main
from ctfkit.commands import start
from ctfkit.registry import TransformError

PNG = b"\x89PNG\r\n\x1a\n"


@pytest.fixture(autouse=True)
def _reset_quiet():
    console.QUIET = False
    yield
    console.QUIET = False


def _zip(members: dict, compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as z:
        for name, content in members.items():
            z.writestr(name, content)
    return buf.getvalue()


def _tar(members: dict, mode="w:gz", links: dict | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as t:
        for name, content in members.items():
            content = content if isinstance(content, bytes) else content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(content)
            t.addfile(info, io.BytesIO(content))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            t.addfile(info)
    return buf.getvalue()


def _write(folder, name, data: bytes) -> str:
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return str(path)


def _names(result, dest) -> set:
    return {os.path.relpath(f, dest).replace(os.sep, "/") for f in result.files}


# ================================================================ unpack

def test_kind_is_decided_by_content_not_extension(tmp_path):
    assert unpack.kind(_write(tmp_path, "a.jpg", _zip({"x": "1"}))) == "zip"
    assert unpack.kind(_write(tmp_path, "b.bin", _tar({"x": "1"}))) == "tar"
    assert unpack.kind(_write(tmp_path, "c.bin", _tar({"x": "1"}, mode="w"))) == "tar"
    assert unpack.kind(_write(tmp_path, "d.dat", gzip.compress(b"plain"))) == "gzip"
    assert unpack.kind(_write(tmp_path, "e.zip", b"not really a zip")) is None
    assert unpack.kind(str(tmp_path / "missing")) is None


def test_zip_after_png_is_not_an_archive(tmp_path):
    # 다른 파일 뒤에 붙은 ZIP 은 "숨은 파일" 이다. 통째로 풀 대상이 아니라 triage 가 안을 들여다본다
    assert unpack.kind(_write(tmp_path, "pic.png", PNG + bytes(50) + _zip({"x": "1"}))) is None


def test_extract_zip_tar_gzip(tmp_path):
    for name, data, expected in [
        ("a.zip", _zip({"one.txt": "1", "sub/two.txt": "2"}), {"one.txt", "sub/two.txt"}),
        ("b.tar.gz", _tar({"one.txt": "1", "sub/two.txt": "2"}), {"one.txt", "sub/two.txt"}),
        ("note.txt.gz", gzip.compress(b"hello"), {"note.txt"}),
    ]:
        dest = tmp_path / ("out_" + name)
        result = unpack.extract(_write(tmp_path, name, data), str(dest))
        assert _names(result, dest) == expected
        assert result.skipped == []


def test_extract_rejects_non_archive(tmp_path):
    with pytest.raises(TransformError):
        unpack.extract(_write(tmp_path, "a.txt", b"hello"), str(tmp_path / "out"))


@pytest.mark.parametrize("bad", ["../escape.txt", "sub/../../escape.txt", "/abs/escape.txt", "C:/escape.txt",
                                 "..\\escape.txt"])
def test_path_traversal_is_refused(tmp_path, bad):
    # 항목 이름이 풀 폴더 밖을 가리키면 쓰지 않는다
    dest = tmp_path / "out"
    result = unpack.extract(_write(tmp_path, "evil.zip", _zip({bad: "pwned", "ok.txt": "fine"})), str(dest))
    assert _names(result, dest) == {"ok.txt"}
    assert any("밖을 가리키는" in s for s in result.skipped)
    assert not (tmp_path / "escape.txt").exists()
    # 풀 폴더 밖에는 아무것도 생기지 않았다
    assert sorted(p.name for p in tmp_path.iterdir()) == ["evil.zip", "out"]


def test_tar_traversal_and_links_are_refused(tmp_path):
    dest = tmp_path / "out"
    data = _tar({"../escape.txt": "pwned", "ok.txt": "fine"}, links={"link": "/etc/passwd"})
    result = unpack.extract(_write(tmp_path, "evil.tar.gz", data), str(dest))
    assert _names(result, dest) == {"ok.txt"}
    assert any("밖을 가리키는" in s for s in result.skipped)
    assert any("일반 파일이 아님" in s for s in result.skipped)
    assert not (tmp_path / "escape.txt").exists()


def test_safe_target():
    root = os.path.realpath("some_dest")
    assert unpack.safe_target("some_dest", "a/b.txt") == os.path.join(root, "a", "b.txt")
    assert unpack.safe_target("some_dest", "./a.txt") == os.path.join(root, "a.txt")
    for bad in ("", ".", "..", "../x", "a/../../x", "/x", "\\x", "C:\\x", "c:x"):
        assert unpack.safe_target("some_dest", bad) is None, bad


def test_oversized_member_is_stopped_by_actual_size(tmp_path):
    # 압축 폭탄: 작게 압축된 큰 파일. 머리에 적힌 크기가 아니라 실제로 푼 양을 세어 멈춘다
    dest = tmp_path / "out"
    limits = unpack.Limits(max_file_size=1000)
    result = unpack.extract(_write(tmp_path, "bomb.zip", _zip({"big": b"\x00" * 100_000, "small": b"ok"})),
                            str(dest), limits)
    assert _names(result, dest) == {"small"}
    assert any("넘음" in s for s in result.skipped)
    assert not (dest / "big").exists()          # 쓰다 만 파일을 남기지 않는다


def test_total_size_and_file_count_limits(tmp_path):
    members = {f"f{i}": b"x" * 400 for i in range(10)}
    dest = tmp_path / "total"
    result = unpack.extract(_write(tmp_path, "t.zip", _zip(members)), str(dest), unpack.Limits(max_total_size=1000))
    assert len(result.files) == 2 and any("전체 풀린 크기" in s for s in result.skipped)

    dest = tmp_path / "count"
    result = unpack.extract(_write(tmp_path, "c.zip", _zip(members)), str(dest), unpack.Limits(max_files=3))
    assert len(result.files) == 3 and any("항목 수" in s for s in result.skipped)


def test_gzip_bomb_is_stopped(tmp_path):
    dest = tmp_path / "out"
    result = unpack.extract(_write(tmp_path, "b.gz", gzip.compress(b"\x00" * 100_000)), str(dest),
                            unpack.Limits(max_file_size=1000))
    assert result.files == [] and any("넘음" in s for s in result.skipped)


def test_broken_archive_does_not_raise(tmp_path):
    data = _zip({"a.txt": "hello" * 100})
    broken = data[:len(data) // 2]                # 뒷부분이 잘린 zip
    path = _write(tmp_path, "broken.zip", b"PK\x03\x04" + broken[4:])
    if unpack.kind(path):                          # 판별에서 걸러지면 그것으로 충분하다
        unpack.extract(path, str(tmp_path / "out"))


# ================================================================ start

def _run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def _nested(tmp_path) -> str:
    """zip 안의 tar.gz 안에, base64(hex(플래그)) 로 적힌 메모가 있다."""
    memo = base64.b64encode(b"DH{nested_archive_flag}".hex().encode())
    inner = _tar({"secret/memo.txt": memo, "secret/pic.png": PNG + bytes(100)})
    return _write(tmp_path, "chall.zip", _zip({"readme.txt": "find the flag\n", "data/inner.tar.gz": inner}))


def test_start_finds_flag_two_archives_deep(tmp_path, capsys):
    # Gate: 압축 파일 하나로 시작해 두 단계 안쪽 파일의 인코딩된 플래그까지 한 번에 찾는다
    code, out, _ = _run(capsys, "start", _nested(tmp_path), "--root", str(tmp_path / "ws"))
    assert code == 0
    assert "플래그: DH{nested_archive_flag}" in out
    assert "extracted/chall.zip/data/inner.tar.gz.d/secret/memo.txt" in out
    assert "(base64→hex)" in out
    assert "파일 5개 (압축 2개 풂)" in out


def test_start_creates_workspace_layout(tmp_path, capsys):
    source = _nested(tmp_path)
    _run(capsys, "start", source, "--root", str(tmp_path / "ws"))
    ws = tmp_path / "ws" / "chall"
    assert (ws / ".ctfkit-workspace").is_file()
    assert (ws / "files" / "chall.zip").read_bytes() == open(source, "rb").read()    # 원본 복사본
    assert (ws / "extracted" / "chall.zip" / "readme.txt").is_file()
    assert (ws / "extracted" / "chall.zip" / "data" / "inner.tar.gz.d" / "secret" / "memo.txt").is_file()
    assert "ctfkit start" in (ws / "commands.log").read_text(encoding="utf-8")
    assert os.path.exists(source)                                                     # 원본은 그대로


def test_notes_record_what_was_checked(tmp_path, capsys):
    _run(capsys, "start", _nested(tmp_path), "--root", str(tmp_path / "ws"))
    notes = (tmp_path / "ws" / "chall" / "notes.md").read_text(encoding="utf-8")
    assert "## 자동 분석 (ctfkit start" in notes
    assert "### 찾은 플래그" in notes and "DH{nested_archive_flag}" in notes
    assert "| `files/chall.zip` | zip 압축 → 2개 풂 |" in notes
    assert "readme.txt` | 글자 파일 (14 바이트) / 내용 find the flag" in notes
    assert "## 풀이 / 플래그" in notes                 # 사람이 채울 틀도 그대로 있다


def test_start_quiet_prints_only_flags(tmp_path, capsys):
    code, out, err = _run(capsys, "-q", "start", _nested(tmp_path), "--root", str(tmp_path / "ws"))
    assert code == 0
    assert out == "DH{nested_archive_flag}\n" and err == ""


def test_start_without_flag_suggests_next_steps(tmp_path, capsys):
    source = _write(tmp_path, "pics.zip", _zip({"a.png": PNG + bytes(100), "note.txt": "nothing here"}))
    code, out, err = _run(capsys, "start", source, "--root", str(tmp_path / "ws"))
    assert code == 1
    assert "플래그를 찾지 못했습니다" in err
    assert "다음: forensic lsb extracted/pics.zip/a.png" in out
    notes = (tmp_path / "ws" / "pics" / "notes.md").read_text(encoding="utf-8")
    assert "### 다음에 해 볼 명령" in notes and "ctfkit forensic lsb" in notes
    assert "### 찾은 플래그" not in notes


def test_start_on_a_single_plain_file(tmp_path, capsys):
    source = _write(tmp_path, "msg.txt", base64.b64encode(b"DH{single_file}"))
    code, out, _ = _run(capsys, "start", source, "--root", str(tmp_path / "ws"), "--name", "warmup")
    assert code == 0
    assert "플래그: DH{single_file}  [files/msg.txt · 파일 본문 (base64)]" in out
    assert (tmp_path / "ws" / "warmup" / "files" / "msg.txt").is_file()


def test_start_on_a_folder_keeps_structure(tmp_path, capsys):
    folder = tmp_path / "download"
    _write(folder, "a/one.txt", b"plain")
    _write(folder, "b/two.zip", _zip({"flag.txt": "DH{in_folder}"}))
    code, out, _ = _run(capsys, "start", str(folder), "--root", str(tmp_path / "ws"))
    assert code == 0 and "DH{in_folder}" in out
    assert (tmp_path / "ws" / "download" / "files" / "a" / "one.txt").is_file()
    assert (tmp_path / "ws" / "download" / "extracted" / "b" / "two.zip" / "flag.txt").is_file()


def test_depth_limit_stops_descending(tmp_path, capsys):
    code, out, _ = _run(capsys, "start", _nested(tmp_path), "--root", str(tmp_path / "ws"), "--depth", "1")
    assert code == 1                                  # 안쪽 tar.gz 를 풀지 않아 플래그를 못 찾는다
    assert "단계 상한 1 에 걸려 풀지 않음" in out
    assert not (tmp_path / "ws" / "chall" / "extracted" / "chall.zip" / "data" / "inner.tar.gz.d").exists()


def test_malicious_archive_cannot_write_outside_workspace(tmp_path, capsys):
    source = _write(tmp_path, "evil.zip", _zip({"../../escape.txt": "pwned", "ok.txt": "DH{still_found}"}))
    code, out, _ = _run(capsys, "start", source, "--root", str(tmp_path / "ws"))
    assert code == 0 and "DH{still_found}" in out
    assert "1개 건너뜀" in out and "밖을 가리키는" in out
    assert not (tmp_path / "escape.txt").exists() and not (tmp_path / "ws" / "escape.txt").exists()


def test_encrypted_members_are_reported_not_extracted(tmp_path, capsys):
    data = bytearray(_zip({"secret.txt": "DH{locked}"}, zipfile.ZIP_STORED))
    # 암호 표시 비트를 켠다 (로컬 헤더와 중앙 디렉터리 양쪽)
    local = data.index(b"PK\x03\x04")
    central = data.index(b"PK\x01\x02")
    data[local + 6] |= 0x01
    data[central + 8] |= 0x01
    code, out, _ = _run(capsys, "start", _write(tmp_path, "locked.zip", bytes(data)), "--root", str(tmp_path / "ws"))
    assert "암호로 잠김" in out
    assert not (tmp_path / "ws" / "locked" / "extracted" / "locked.zip" / "secret.txt").exists()


def test_existing_workspace_is_not_overwritten(tmp_path, capsys):
    source = _nested(tmp_path)
    _run(capsys, "start", source, "--root", str(tmp_path / "ws"))
    code, out, err = _run(capsys, "start", source, "--root", str(tmp_path / "ws"))
    assert code == 2 and "이미 있는 폴더" in err
    code, _, _ = _run(capsys, "start", source, "--root", str(tmp_path / "ws"), "--name", "again")
    assert code == 0


@pytest.mark.parametrize("argv, message", [
    (["no_such_file.zip"], "파일이나 폴더가 아닙니다"),
    (["{empty}"], "폴더가 비어 있습니다"),
    (["{file}", "--depth", "-1"], "--depth"),
    (["{file}", "--flag", "("], "정규식"),
])
def test_start_input_errors(tmp_path, capsys, argv, message):
    empty = tmp_path / "empty"
    empty.mkdir()
    values = {"empty": str(empty), "file": _nested(tmp_path)}
    argv = [a.format(**values) if a.startswith("{") else a for a in argv]
    code, out, err = _run(capsys, "start", *argv, "--root", str(tmp_path / "ws"))
    assert code == 2 and message in err and out == ""


def test_large_file_is_listed_but_not_analyzed(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(start, "MAX_ANALYZE_SIZE", 50)
    source = _write(tmp_path, "big.bin", b"A" * 200 + b"DH{too_big_to_scan}")
    code, out, _ = _run(capsys, "start", source, "--root", str(tmp_path / "ws"))
    assert code == 1
    assert "너무 커서 분석하지 않음" in out and "DH{too_big_to_scan}" not in out


def test_default_name_strips_archive_extensions():
    assert start._default_name("dir/chall.tar.gz") == "chall"
    assert start._default_name("chall.zip") == "chall"
    assert start._default_name("folder/") == "folder"
    assert start._default_name("noext") == "noext"
