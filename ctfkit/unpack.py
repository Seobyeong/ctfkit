"""압축 파일을 안전하게 푼다 (zip, tar, tar.gz/bz2/xz, gzip, cpio, 디스크 이미지 EWF·NTFS). 표준 라이브러리만 사용한다.

CTF 문제 파일은 남이 만든 것이다. 그대로 믿고 풀면 안 되는 경우가 세 가지 있다.

  1. 경로 탈출: 항목 이름이 "../../home/me/.bashrc" 나 절대 경로면 풀 폴더 밖의 파일을 덮어쓴다.
  2. 압축 폭탄: 몇 KB 짜리가 몇 GB 로 풀려 디스크와 메모리를 다 쓴다. 머리에 적힌 크기는 거짓일 수 있으므로
     실제로 푼 양을 세면서 상한에서 멈춘다.
  3. 링크·장치 파일: tar 안의 심볼릭 링크는 폴더 밖을 가리킬 수 있다. 일반 파일만 푼다.

그래서 extractall() 을 쓰지 않고 항목을 하나씩 검사하며 직접 쓴다.
"""

import gzip
import io
import os
import struct
import tarfile
import zipfile
from dataclasses import dataclass, field

from ctfkit.registry import TransformError

_CHUNK = 1024 * 1024


@dataclass
class Limits:
    max_files: int = 500                      # 압축 파일 하나에서 푸는 항목 수
    max_file_size: int = 50 * 1024 * 1024     # 항목 하나의 풀린 크기
    max_total_size: int = 200 * 1024 * 1024   # 압축 파일 하나에서 풀리는 전체 크기


@dataclass
class Extracted:
    files: list = field(default_factory=list)     # 풀어서 만든 파일의 경로
    skipped: list = field(default_factory=list)   # 풀지 않은 항목과 이유 ("이름: 이유")
    notes: list = field(default_factory=list)     # 푼 것에 대한 설명 (디스크 이미지: 지운 파일 수, 백업 부트 섹터 등)
    labels: dict = field(default_factory=dict)    # 풀어서 만든 파일 경로 → 설명 ("지운 파일" 등)


def kind(path: str) -> str | None:
    """파일 내용으로 압축 종류를 판별한다: "zip" / "tar" / "gzip" / "cpio" / "ewf" / "ntfs" / None. 확장자는 보지 않는다."""
    from ctfkit import disk

    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except OSError:
        return None
    if disk.is_ewf(head):
        return "ewf"
    if head[3:11] == disk.NTFS_OEM:
        return "ntfs" if disk.looks_like_disk(path) else None
    head = head[:6]
    if head in _CPIO_MAGIC:
        return "cpio"
    # 맨 앞이 PK 인 것만 zip 으로 본다. 다른 파일 뒤에 붙은 zip(PNG+ZIP)은 압축 파일이 아니라 "숨은 파일" 이다
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip" if zipfile.is_zipfile(path) else None
    try:
        # 항목이 하나라도 있어야 tar 로 본다. 0 으로 채워진 데이터는 "빈 tar" 로도 읽히기 때문이다
        if tarfile.is_tarfile(path):
            with tarfile.open(path, "r:*") as tf:
                if tf.next() is not None:
                    return "tar"
    except (OSError, tarfile.TarError, EOFError):
        pass
    if head[:3] == b"\x1f\x8b\x08":
        return "gzip"
    # 파티션 표가 있거나 부트 섹터가 망가진 디스크 이미지 (볼륨 끝의 백업 부트 섹터로 알아본다)
    if disk.looks_like_disk(path):
        return "ntfs"
    return None


def longest_name(path: str) -> int:
    """압축 안 항목 이름 중 가장 긴 것의 길이 (풀 폴더의 경로 길이를 정할 때 쓴다). 읽을 수 없으면 0."""
    try:
        what = kind(path)
        if what == "zip":
            with zipfile.ZipFile(path) as zf:
                return max((len(n) for n in zf.namelist()), default=0)
        if what == "tar":
            with tarfile.open(path, "r:*") as tf:
                return max((len(m.name) for m in tf.getmembers()), default=0)
        if what == "gzip":
            return len(os.path.basename(path))
        if what == "cpio":
            with open(path, "rb") as f:
                return max((len(name) for name, _, _ in _cpio_entries(f)), default=0)
        if what == "ewf":
            return len(os.path.basename(path)) + 4
        if what == "ntfs":
            from ctfkit import disk

            return disk.ntfs_longest_name(path)
    except (OSError, zipfile.BadZipFile, tarfile.TarError, EOFError):
        pass
    return 0


def safe_target(dest: str, name: str) -> str | None:
    """항목 이름 name 을 dest 안의 경로로 바꾼다. dest 밖을 가리키면 None."""
    name = name.replace("\\", "/")
    # 절대 경로, 드라이브 문자, 상위 폴더 참조는 받지 않는다
    if not name or name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return None
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    target = os.path.realpath(os.path.join(dest, *parts))
    root = os.path.realpath(dest)
    try:
        inside = os.path.commonpath([root, target]) == root
    except ValueError:   # Windows 에서 드라이브가 다르면
        inside = False
    return target if inside and target != root else None


class _Budget:
    """압축 파일 하나를 푸는 동안 쓴 양을 센다."""

    def __init__(self, limits: Limits):
        self.limits = limits
        self.files = 0
        self.total = 0

    def write(self, source, target: str) -> str | None:
        """source(읽기 가능한 객체)를 target 에 쓴다. 상한을 넘으면 쓰던 파일을 지우고 이유를 돌려준다."""
        os.makedirs(os.path.dirname(target), exist_ok=True)
        written = 0
        reason = None
        try:
            with open(target, "wb") as out:
                while True:
                    chunk = source.read(_CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    # 머리에 적힌 크기를 믿지 않고, 실제로 읽은 양으로 판단한다
                    if written > self.limits.max_file_size:
                        reason = f"풀린 크기가 {self.limits.max_file_size} 바이트를 넘음"
                        break
                    if self.total + written > self.limits.max_total_size:
                        reason = f"전체 풀린 크기가 {self.limits.max_total_size} 바이트를 넘음"
                        break
                    out.write(chunk)
        except (OSError, EOFError, zipfile.BadZipFile, tarfile.TarError, RuntimeError, NotImplementedError,
                gzip.BadGzipFile) as e:
            reason = f"읽기 실패 ({e})"
        if reason:
            try:
                os.remove(target)
            except OSError:
                pass
            return reason
        self.files += 1
        self.total += written
        return None

    @property
    def full(self) -> bool:
        return self.files >= self.limits.max_files


def extract(path: str, dest: str, limits: Limits | None = None) -> Extracted:
    """path 를 dest 폴더에 푼다. 풀 수 없는 형식이면 TransformError."""
    limits = limits or Limits()
    what = kind(path)
    if what is None:
        raise TransformError(f"풀 수 있는 압축 파일이 아닙니다: {path}")
    os.makedirs(dest, exist_ok=True)
    result = Extracted()
    budget = _Budget(limits)
    try:
        {"zip": _zip, "tar": _tar, "gzip": _gzip, "cpio": _cpio, "ewf": _ewf, "ntfs": _ntfs}[what](path, dest, budget, result)
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, ValueError) as e:
        result.skipped.append(f"(압축 파일 전체): 읽기 실패 ({e})")
    return result


def _zip(path, dest, budget, result) -> None:
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if budget.full:
                result.skipped.append(f"(나머지 항목): 항목 수가 {budget.limits.max_files}개를 넘음")
                break
            target = safe_target(dest, info.filename)
            if target is None:
                result.skipped.append(f"{info.filename}: 풀 폴더 밖을 가리키는 경로")
                continue
            if info.flag_bits & 0x1:
                result.skipped.append(f"{info.filename}: 암호로 잠김")
                continue
            try:
                source = zf.open(info)
            except (RuntimeError, NotImplementedError, zipfile.BadZipFile) as e:
                result.skipped.append(f"{info.filename}: 읽기 실패 ({e})")
                continue
            with source:
                reason = budget.write(source, target)
            if reason:
                result.skipped.append(f"{info.filename}: {reason}")
            else:
                result.files.append(target)


def _tar(path, dest, budget, result) -> None:
    with tarfile.open(path, "r:*") as tf:
        for member in tf:
            if member.isdir():
                continue
            if budget.full:
                result.skipped.append(f"(나머지 항목): 항목 수가 {budget.limits.max_files}개를 넘음")
                break
            if not member.isreg():
                result.skipped.append(f"{member.name}: 일반 파일이 아님 (링크·장치 파일은 풀지 않음)")
                continue
            target = safe_target(dest, member.name)
            if target is None:
                result.skipped.append(f"{member.name}: 풀 폴더 밖을 가리키는 경로")
                continue
            source = tf.extractfile(member)
            if source is None:
                result.skipped.append(f"{member.name}: 읽기 실패")
                continue
            with source:
                reason = budget.write(source, target)
            if reason:
                result.skipped.append(f"{member.name}: {reason}")
            else:
                result.files.append(target)


# cpio: 리눅스 initramfs(rootfs.cpio) 의 형식. newc("070701"), newc+crc("070702"), odc("070707") 를 읽는다
_CPIO_MAGIC = (b"070701", b"070702", b"070707")
_S_IFMT, _S_IFREG = 0o170000, 0o100000


class _Limited:
    """파일 객체에서 n 바이트만 읽게 한다 (cpio 항목 하나의 내용)."""

    def __init__(self, f, n: int):
        self.f, self.left = f, n

    def read(self, size: int = -1) -> bytes:
        size = self.left if size < 0 else min(size, self.left)
        data = self.f.read(size)
        self.left -= len(data)
        return data


def _cpio_entries(f, on_entry=None):
    """(이름, 모드, 크기) 를 차례로 낸다. on_entry(이름, 모드, 크기, 파일 객체) 를 주면 내용을 그 안에서 읽게 하고,
    읽고 남은 부분은 건너뛴다."""
    while True:
        magic = f.read(6)
        if magic in (b"070701", b"070702"):
            fields = f.read(104)
            if len(fields) < 104:
                return
            values = [int(fields[i:i + 8], 16) for i in range(0, 104, 8)]
            mode, size, name_size, header, align = values[1], values[6], values[11], 110, 4
        elif magic == b"070707":
            fields = f.read(70)
            if len(fields) < 70:
                return
            mode, name_size, size = int(fields[12:18], 8), int(fields[53:59], 8), int(fields[59:70], 8)
            header, align = 76, 1
        else:
            return
        name = f.read(name_size).rstrip(b"\x00").decode("utf-8", "replace")
        f.read(-(header + name_size) % align)
        if name == "TRAILER!!!":
            return
        start = f.tell()
        if on_entry is not None:
            on_entry(name, mode, size, _Limited(f, size))
        f.seek(start + size + (-size % align))
        yield name, mode, size


def _cpio(path, dest, budget, result) -> None:
    links = 0

    def write(name, mode, size, source):
        nonlocal links
        if mode & _S_IFMT != _S_IFREG:
            links += (mode & _S_IFMT) == 0o120000
            return
        if budget.full:
            if not any(s.startswith("(나머지 항목)") for s in result.skipped):
                result.skipped.append(f"(나머지 항목): 항목 수가 {budget.limits.max_files}개를 넘음")
            return
        target = safe_target(dest, name)
        if target is None:
            result.skipped.append(f"{name}: 풀 폴더 밖을 가리키는 경로")
            return
        reason = budget.write(source, target)
        if reason:
            result.skipped.append(f"{name}: {reason}")
        else:
            result.files.append(target)

    with open(path, "rb") as f:
        for _ in _cpio_entries(f, write):
            pass
    if links:
        result.skipped.append(f"(링크 {links}개): 일반 파일이 아님 (링크·장치 파일은 풀지 않음)")


def _gzip(path, dest, budget, result) -> None:
    # gzip 은 파일 하나만 담는다. 이름은 원래 이름에서 .gz 를 뗀 것으로 한다
    name = os.path.basename(path)
    name = name[:-3] if name.lower().endswith(".gz") and len(name) > 3 else name + ".out"
    target = safe_target(dest, name)
    if target is None:
        result.skipped.append(f"{name}: 풀 폴더 밖을 가리키는 경로")
        return
    with gzip.open(path, "rb") as source:
        reason = budget.write(source, target)
    if reason:
        result.skipped.append(f"{name}: {reason}")
    else:
        result.files.append(target)


# 디스크 이미지. 압축 폭탄과 같은 위험이 있다 (몇 백 KB 의 E01 이 수백 MB 로 풀린다). 같은 상한을 쓴다

def _remove(path) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _ewf(path, dest, budget, result) -> None:
    """EnCase 이미지(E01) → 원본 디스크 하나 (이름.raw). 안의 파일 시스템은 다음 단계에서 ntfs 로 푼다."""
    from ctfkit import disk

    name = os.path.splitext(os.path.basename(path))[0] + ".raw"
    target = safe_target(dest, name)
    if target is None:
        result.skipped.append(f"{name}: 풀 폴더 밖을 가리키는 경로")
        return
    try:
        info = disk.ewf_info(path)
        reason = budget.write(disk.GenReader(disk.ewf_read(path, budget.limits.max_file_size)), target)
    except disk.DiskError as e:
        _remove(target)
        result.skipped.append(f"{name}: {e}")
        return
    if reason:
        result.skipped.append(f"{name}: {reason}")
        return
    result.files.append(target)
    segs = len(disk.ewf_segments(path))
    result.notes.append(f"원본 디스크 {info.size} 바이트" + (f" (조각 {segs}개)" if segs > 1 else ""))


def _ntfs(path, dest, budget, result) -> None:
    """디스크 이미지 안 NTFS 의 파일, 지운 파일(_deleted/), ADS(이름~스트림), 미할당 데이터 덩어리(_unallocated/)."""
    from ctfkit import disk

    notes = []
    try:
        for item in disk.ntfs_items(path, budget.limits.max_file_size, budget.limits.max_total_size - budget.total, notes):
            if budget.full:
                result.skipped.append(f"(나머지 항목): 항목 수가 {budget.limits.max_files}개를 넘음")
                break
            target = safe_target(dest, item.rel)
            if target is None:
                result.skipped.append(f"{item.rel}: 풀 폴더 밖을 가리키는 경로")
                continue
            reason = budget.write(io.BytesIO(item.data), target)
            if reason:
                result.skipped.append(f"{item.rel}: {reason}")
                continue
            result.files.append(target)
            if item.note:
                result.labels[target] = item.note
    except (disk.DiskError, struct.error, IndexError) as e:
        result.skipped.append(f"(파일 시스템): 읽기 실패 ({e})")
    result.notes += notes
