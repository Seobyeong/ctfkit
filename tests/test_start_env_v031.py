"""커널·VM 같은 큰 실제 문제에서 start 가 헛걸음을 안내하던 여섯 가지.

1. 실행 환경 파일(QEMU, 커널 이미지, UEFI 펌웨어)을 공격 대상처럼 안내함 → 분석하지 않고 한 줄로 묶는다
2. 빌드·배포 설정(Dockerfile, *.config)의 숫자를 values.json 에 모음 → 모으지 않는다
3. 출제자가 바꾼 부분(패치)이 다른 파일에 묻힘 → AGENTS.md 맨 앞에 둔다
4. 같은 내용을 두 번 분석함 → 해시로 한 번만
5. 50MB 넘는 항목(디스크 이미지 등)을 풀지 않음 → start 는 항목당 256MB 까지
6. 윈도우 260자 경로 제한으로 깊은 항목을 못 읽음 → 짧은 폴더 x/<해시>/
그리고 실행 파일 안의 우연한 시그니처를 "숨은 파일" 로 보고하지 않는다.
"""

import struct
import zipfile

from ctfkit.cli import main
from ctfkit.commands import start, triage


def _zip(path, files):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return str(path)


def _start(tmp_path, source, capsys):
    main(["start", source, "--root", str(tmp_path / "ws"), "--name", "c"])
    out = capsys.readouterr().out
    return out, (tmp_path / "ws" / "c" / "AGENTS.md").read_text(encoding="utf-8")


def test_classify_by_name_only():
    assert start.classify("a/qemu-system-aarch64") == ("환경", "QEMU 에뮬레이터")
    assert start.classify("Image.gz")[0] == "환경" and start.classify("bzImage")[0] == "환경"
    assert start.classify("uImage")[0] == "환경"
    assert start.classify("QEMU_EFI.fd")[0] == "환경"
    assert start.classify("qemu-system-aarch64-7.1.0-r7.apk")[0] == "환경"
    assert start.classify("Dockerfile")[0] == "빌드" and start.classify("linux.config")[0] == "빌드"
    for name in ("prob", "chall", "vuln.ko", "rootfs.cpio", "bl32.bin", "disk.img", "run.sh", "Imagefile.png"):
        assert start.classify(name) == (None, None), name


def test_environment_build_and_patch_files(tmp_path, capsys):
    elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 200
    source = _zip(tmp_path / "chall.zip", {
        "deploy/qemu-system-x86_64": elf,
        "deploy/bzImage": b"MZ" + b"\x00" * 300,
        "Dockerfile": "FROM ubuntu:24.04\nENV LISTEN=8080\n",
        "src/vuln.patch": "diff --git a/x.c b/x.c\n--- a/x.c\n+++ b/x.c\n@@ -1 +1 @@\n-a\n+b\n",
        "out.txt": "n = 3233\ne = 17\nc = 2790\n",
    })
    out, agents = _start(tmp_path, source, capsys)
    lines = agents.split("## 파일\n", 1)[1].splitlines()
    assert "src/vuln.patch: **패치" in lines[0]                                   # 패치가 맨 앞
    env = next(line for line in lines if line.startswith("- 실행 환경"))
    assert "2개:" in env and "qemu-system-x86_64" in env and "bzImage" in env
    assert "빌드·배포 설정 1개: Dockerfile" in agents
    assert "template pwn" not in agents and "qemu-system-x86_64" not in out.split("다음:")[-1]
    values = (tmp_path / "ws" / "c" / "values.json").read_text(encoding="utf-8")
    assert '"n": 3233' in values and "LISTEN" not in values


def test_same_content_is_analyzed_once(tmp_path, capsys):
    inner = tmp_path / "inner.zip"
    _zip(inner, {"memo.txt": "hello there\n"})
    source = _zip(tmp_path / "outer.zip", {"inner.zip": inner.read_bytes(), "copy/inner.zip": inner.read_bytes()})
    out, agents = _start(tmp_path, source, capsys)
    assert "와 내용이 같음 (다시 분석하지 않음)" in out
    assert "같은 내용이라 건너뛴 파일 1개: inner.zip" in agents
    assert out.count("memo.txt: 글자 파일") == 1


def test_start_unpacks_entries_larger_than_the_default_limit(tmp_path, capsys, monkeypatch):
    assert start.START_LIMITS.max_file_size > 64 * 1024 * 1024     # 64MB 디스크 이미지를 받아야 한다
    monkeypatch.setattr(start, "START_LIMITS", start.unpack.Limits(max_file_size=10))
    out, _ = _start(tmp_path, _zip(tmp_path / "a.zip", {"disk.img": b"\x00" * 100}), capsys)
    assert "1개 건너뜀 (disk.img: 풀린 크기가 10 바이트를 넘음)" in out


def test_long_extract_path_uses_short_folder(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(start.os, "name", "nt")
    monkeypatch.setattr(start, "LONG_PATH", 10)
    inner = tmp_path / "inner.zip"
    _zip(inner, {"deep/name.txt": "DH{short_path_still_read}"})
    out, _ = _start(tmp_path, _zip(tmp_path / "outer.zip", {"inner.zip": inner.read_bytes()}), capsys)
    assert "플래그: DH{short_path_still_read}" in out and "(x/" in out


def _elf_with(body: bytes, tail: bytes) -> bytes:
    """섹션 헤더 1개짜리 64비트 ELF. 본문 뒤에 섹션 헤더가 있고, 그 뒤가 '실행 파일의 끝 뒤' 다."""
    shoff = 64 + len(body)
    header = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0, 0, shoff, 0, 64, 56, 0, 64, 1, 0)
    return header + body + b"\x00" * 64 + tail


def test_signatures_inside_executable_are_not_hidden_files(tmp_path):
    data = _elf_with(b"code" + b"\xff\xd8\xff\xe0" + b"\x1f\x8b\x08" + b"more", b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)
    assert triage.executable_end(data) == 64 + 15 + 64
    path = tmp_path / "prog"
    path.write_bytes(data)
    report = triage.analyze(str(path), triage.compile_pattern(None), use_external=False)
    hidden = dict(report.items).get("숨은 파일", "")
    assert "PNG" in hidden and "JPEG" not in hidden and "GZIP" not in hidden
    assert triage.executable_end(b"not an executable") is None
