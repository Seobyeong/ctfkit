"""cpio (리눅스 initramfs) 풀기와 start 의 rootfs 요약.

커널·TEE 문제의 rootfs.cpio 에는 출제자가 넣은 파일(/root/flag.enc, 트리 밖 커널 모듈, 시작 스크립트)이 수백 개의 배포판 파일과 섞여 있다.
"""

import gzip
import os

import pytest

from ctfkit import unpack
from ctfkit.cli import main
from ctfkit.commands import start

REG, DIR, LNK = 0o100644, 0o040755, 0o120777


def newc(entries) -> bytes:
    """[(이름, 모드, 내용)] → newc cpio."""
    out = b""
    for ino, (name, mode, data) in enumerate(list(entries) + [("TRAILER!!!", 0, b"")], 1):
        raw = name.encode() + b"\x00"
        fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(raw), 0]
        header = b"070701" + b"".join(b"%08X" % f for f in fields)
        out += header + raw + b"\x00" * (-(len(header) + len(raw)) % 4)
        out += data + b"\x00" * (-len(data) % 4)
    return out


def odc(entries) -> bytes:
    out = b""
    for name, mode, data in list(entries) + [("TRAILER!!!", 0, b"")]:
        raw = name.encode() + b"\x00"
        out += (b"070707" + b"%06o" % 0 + b"%06o" % 1 + b"%06o" % mode + b"%06o" % 0 * 2 + b"%06o" % 1 + b"%06o" % 0
                + b"%011o" % 0 + b"%06o" % len(raw) + b"%011o" % len(data) + raw + data)
    return out


@pytest.mark.parametrize("build", [newc, odc])
def test_cpio_extracts_regular_files_only(tmp_path, build):
    path = tmp_path / "rootfs.cpio"
    path.write_bytes(build([("root", DIR, b""), ("root/flag.enc", REG, b"\x01\x02secret"),
                            ("bin/sh", LNK, b"busybox"), ("init", REG, b"#!/bin/sh\nexec /sbin/init\n")]))
    assert unpack.kind(str(path)) == "cpio"
    result = unpack.extract(str(path), str(tmp_path / "out"))
    names = sorted(os.path.relpath(f, tmp_path / "out").replace(os.sep, "/") for f in result.files)
    assert names == ["init", "root/flag.enc"]
    assert (tmp_path / "out" / "root" / "flag.enc").read_bytes() == b"\x01\x02secret"
    assert result.skipped == ["(링크 1개): 일반 파일이 아님 (링크·장치 파일은 풀지 않음)"]


def test_cpio_refuses_paths_outside_and_respects_limits(tmp_path):
    path = tmp_path / "evil.cpio"
    path.write_bytes(newc([("../escape", REG, b"x"), ("big", REG, b"A" * 100)]))
    result = unpack.extract(str(path), str(tmp_path / "out"), unpack.Limits(max_file_size=10))
    assert not (tmp_path / "escape").exists() and result.files == []
    assert any("폴더 밖" in s for s in result.skipped) and any("10 바이트를 넘음" in s for s in result.skipped)


def test_start_summarizes_rootfs(tmp_path, capsys):
    files = [("lib/libc.so.6", REG, b"\x7fELF" + b"\x00" * 60), ("usr/bin/env", REG, b"\x7fELF" + b"\x00" * 60),
             ("lib/modules/5.15.94/kernel/net/llc/llc.ko", REG, b"\x7fELF" + b"\x00" * 60),
             ("lib/modules/5.15.94/extra/vuln.ko", REG, b"\x7fELF" + b"\x00" * 60),
             ("etc/init.d/rcS", REG, b"#!/bin/sh\n"), ("etc/init.d/S99chall", REG, b"#!/bin/sh\n/root/chall &\n"),
             ("root/flag.enc", REG, b"\x8f\x13\x00\x91" * 8), ("init", REG, b"#!/bin/sh\nexec /sbin/init\n")]
    (tmp_path / "chall").mkdir()
    (tmp_path / "chall" / "rootfs.cpio.gz").write_bytes(gzip.compress(newc(files)))
    main(["start", str(tmp_path / "chall"), "--root", str(tmp_path / "ws"), "--name", "c"])
    out = capsys.readouterr().out
    agents = (tmp_path / "ws" / "c" / "AGENTS.md").read_text(encoding="utf-8")
    assert "cpio 압축 → 8개 풂" in agents
    assert "배포판 경로(lib·usr·bin·etc 등) 5개는 분석하지 않음 (커널 트리 안의 모듈 1개 포함)" in agents
    assert "시작 스크립트 etc/init.d: S99chall, rcS" in agents
    for name in ("root/flag.enc", "extra/vuln.ko", "/init"):
        assert name in agents, name
    assert "libc.so.6" not in agents and "llc.ko" not in agents and "libc.so.6" not in out
    assert start.DEFAULT_DEPTH >= 5   # zip → tar.gz → tar → rootfs.cpio.gz → cpio
