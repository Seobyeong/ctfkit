"""디스크 이미지 포렌식: EWF(E01) 풀기, NTFS 파일·지운 파일·미할당 데이터 꺼내기. 표준 라이브러리만 사용한다.

평가용 포렌식 문제(E01 두 개)에서 ctfkit 은 파일을 "알 수 없음" 으로만 보여 줬고, 에이전트는 실행마다 같은 일을 했다:
EWF 압축 풀기 → NTFS MFT 파서 → 파일 꺼내기 → 미할당 영역 찾기. 스크립트를 쓰는 글이 비용의 절반을 넘었다.
그 반복을 여기서 한 번에 한다. 공격(무엇이 플래그인가)은 추측하지 않고, 디스크에 있는 것을 꺼내 보여 주기만 한다.

  EWF   : EnCase 이미지(.E01). 32KB 덩어리를 zlib 으로 압축해 담는다. 조각 파일(.E02 ...)이 옆에 있으면 이어 읽는다.
  NTFS  : 부트 섹터 → MFT(조각나 있을 수 있음) → 레코드마다 이름·부모·데이터. 부트 섹터가 망가졌으면 볼륨 끝의 백업을 읽는다.
          지운 파일(레코드는 남아 있음), 이름 붙은 데이터 스트림(ADS), 미할당 클러스터의 데이터 덩어리를 꺼낸다.

남이 만든 이미지다. 머리에 적힌 크기·위치를 믿지 않고, 읽는 양에 상한을 둔다 (unpack 의 상한과 같은 역할).
"""

from __future__ import annotations

import os
import re
import struct
import zlib
from dataclasses import dataclass, field

EWF_MAGIC = b"EVF\x09\x0d\x0a\xff\x00"
SECTOR = 512
NTFS_OEM = b"NTFS    "
MAX_RECORDS = 200_000          # MFT 레코드 수 상한
MAX_UNALLOC_RUNS = 64          # 꺼낼 미할당 덩어리 수
MAX_UNALLOC_TOTAL = 64 << 20   # 미할당 덩어리 전체 크기
MAX_UNALLOC_RUN = 16 << 20     # 덩어리 하나의 크기 (더 크면 앞부분만)
FIRST_USER_RECORD = 24         # 0~23 은 $MFT·$Bitmap 같은 시스템 레코드
_BAD_NAME = re.compile(r'[<>:"|?*\x00-\x1f]')


class DiskError(Exception):
    pass


# ---------------------------------------------------------------- EWF (E01)

def is_ewf(head: bytes) -> bool:
    return head.startswith(EWF_MAGIC)


def ewf_segments(path: str) -> list[str]:
    """첫 조각(.E01) 옆에 있는 이어지는 조각들 (.E02, .E03 ...). 없으면 [path]."""
    stem, ext = os.path.splitext(path)
    if len(ext) != 4 or ext[1:].lower() != "e01":
        return [path]
    out = [path]
    for n in range(2, 100):
        for name in (f"{stem}{ext[:2]}{n:02d}", f"{stem}.E{n:02d}", f"{stem}.e{n:02d}"):
            if os.path.isfile(name):
                out.append(name)
                break
        else:
            break
    return out


def _sections(f):
    """(종류, 위치, 다음 위치, 크기). 위치는 76바이트 구역 설명의 시작."""
    pos = 13
    seen = set()
    while pos not in seen:
        seen.add(pos)
        f.seek(pos)
        desc = f.read(76)
        if len(desc) < 76:
            return
        kind = desc[:16].rstrip(b"\x00").decode("ascii", "replace")
        nxt, size = struct.unpack_from("<QQ", desc, 16)
        yield kind, pos, nxt, size
        if kind in ("done", "next") or nxt <= pos:
            return
        pos = nxt


@dataclass
class EwfInfo:
    size: int = 0                 # 원본 디스크 크기 (바이트)
    chunk: int = 0                # 덩어리 하나의 크기
    segments: int = 1
    missing_segment: bool = False  # 마지막 조각이 "next" 로 끝나는데 다음 파일이 없음


def ewf_info(path: str) -> EwfInfo:
    info = EwfInfo()
    with open(path, "rb") as f:
        if not is_ewf(f.read(8)):
            raise DiskError("EWF(E01) 머리가 아닙니다")
        for kind, pos, _, _ in _sections(f):
            if kind in ("volume", "disk"):
                f.seek(pos + 76)
                v = f.read(24)
                spc, bps, sectors = struct.unpack_from("<IIQ", v, 8)
                info.chunk, info.size = spc * bps, sectors * bps
    if not info.chunk:
        raise DiskError("EWF 의 volume 구역(디스크 크기)을 찾지 못했습니다")
    return info


def ewf_read(path: str, limit: int):
    """원본 디스크를 덩어리 단위로 낸다 (생성기). 합계가 limit 를 넘으면 DiskError."""
    info = ewf_info(path)
    if info.size > limit:
        raise DiskError(f"원본 디스크 크기 {info.size} 바이트가 상한 {limit} 바이트를 넘음")
    left = info.size
    segs = ewf_segments(path)
    for seg in segs:
        with open(seg, "rb") as f:
            if not is_ewf(f.read(8)):
                raise DiskError(f"EWF 조각이 아닙니다: {os.path.basename(seg)}")
            sectors_end = None
            last = None
            for kind, pos, nxt, size in _sections(f):
                last = kind
                if kind == "sectors":
                    sectors_end = pos + size
                elif kind == "table":
                    f.seek(pos + 76)
                    head = f.read(24)
                    count, = struct.unpack_from("<I", head, 0)
                    base, = struct.unpack_from("<Q", head, 8)
                    raw = f.read(4 * count)
                    entries = struct.unpack(f"<{len(raw) // 4}I", raw[:len(raw) // 4 * 4])
                    offsets = [(base + (e & 0x7FFFFFFF), bool(e >> 31)) for e in entries]
                    end_of_last = sectors_end if sectors_end and sectors_end > (offsets[-1][0] if offsets else 0) else pos
                    for i, (off, packed) in enumerate(offsets):
                        if left <= 0:
                            return
                        end = offsets[i + 1][0] if i + 1 < len(offsets) else end_of_last
                        f.seek(off)
                        blob = f.read(max(0, min(end - off, info.chunk + 64)))
                        if packed:
                            try:
                                data = zlib.decompressobj().decompress(blob, info.chunk)
                            except zlib.error as e:
                                raise DiskError(f"EWF 덩어리 압축 풀기 실패 (위치 {off}): {e}") from e
                        else:
                            data = blob[:info.chunk]
                        data = data[:min(info.chunk, left)]
                        left -= len(data)
                        yield data
            if last == "next" and seg == segs[-1]:
                raise DiskError("다음 EWF 조각(.E02 등)이 없어 디스크 뒷부분을 읽지 못함")
    if left > 0:
        raise DiskError(f"EWF 표가 디스크 크기보다 짧음 ({left} 바이트 모자람)")


class GenReader:
    """생성기를 read() 가 되는 객체로 (unpack._Budget.write 가 쓴다)."""

    def __init__(self, gen):
        self.gen, self.buf = gen, b""

    def read(self, size: int = -1) -> bytes:
        while size < 0 or len(self.buf) < size:
            try:
                self.buf += next(self.gen)
            except StopIteration:
                break
        if size < 0:
            out, self.buf = self.buf, b""
        else:
            out, self.buf = self.buf[:size], self.buf[size:]
        return out


# ---------------------------------------------------------------- NTFS

@dataclass
class Volume:
    offset: int                 # 이미지 안에서 볼륨이 시작하는 바이트
    bps: int
    cluster: int
    mft_lcn: int
    record: int
    total_sectors: int
    backup: bool = False        # 망가진 부트 섹터 대신 볼륨 끝의 백업으로 읽었나
    label: str = ""

    @property
    def size(self) -> int:
        return self.total_sectors * self.bps


def _boot(sector: bytes, offset: int, backup: bool = False) -> Volume | None:
    if len(sector) < 512 or sector[3:11] != NTFS_OEM:
        return None
    bps, spc = struct.unpack_from("<HB", sector, 11)
    total, mft_lcn = struct.unpack_from("<QQ", sector, 0x28)
    rec = struct.unpack_from("<b", sector, 0x40)[0]
    if bps not in (512, 1024, 2048, 4096) or spc == 0:
        return None
    if spc > 128:            # 큰 클러스터는 2^(256-값) 으로 적는다
        spc = 1 << (256 - spc)
    cluster = bps * spc
    record = (1 << -rec) if rec < 0 else rec * cluster
    if record not in (1024, 2048, 4096) or total == 0:
        return None
    return Volume(offset, bps, cluster, mft_lcn, record, total, backup)


def _partitions(f, size: int) -> list[tuple[int, int]]:
    """MBR·GPT 의 파티션 (시작 바이트, 크기). 표가 없으면 []."""
    f.seek(0)
    mbr = f.read(512)
    if len(mbr) < 512 or mbr[510:512] != b"\x55\xaa":
        return []
    parts = []
    gpt = False
    for i in range(4):
        e = mbr[446 + 16 * i:462 + 16 * i]
        ptype, = struct.unpack_from("<B", e, 4)
        lba, count = struct.unpack_from("<II", e, 8)
        if ptype == 0xEE:
            gpt = True
        elif ptype and count and lba * SECTOR < size:
            parts.append((lba * SECTOR, count * SECTOR))
    if gpt:
        f.seek(SECTOR)
        head = f.read(92)
        if head[:8] == b"EFI PART":
            lba, n, esize = struct.unpack_from("<QII", head, 72)
            n = min(n, 256)
            f.seek(lba * SECTOR)
            table = f.read(n * esize)
            for i in range(n):
                e = table[i * esize:(i + 1) * esize]
                if len(e) < 48 or not e[:16].strip(b"\x00"):
                    continue
                first, last = struct.unpack_from("<QQ", e, 32)
                if first * SECTOR < size:
                    parts.append((first * SECTOR, (last - first + 1) * SECTOR))
    return parts


def find_volumes(path: str) -> list[Volume]:
    """이미지 안의 NTFS 볼륨들. 맨 앞, 파티션 표, 망가진 부트 섹터면 볼륨 끝의 백업 순서로 찾는다."""
    size = os.path.getsize(path)
    if size < 16 * SECTOR:
        return []
    found = []
    with open(path, "rb") as f:
        f.seek(0)
        first = f.read(512)
        candidates = [(0, size)] + _partitions(f, size)
        for start, length in candidates:
            f.seek(start)
            vol = _boot(f.read(512), start) if start else _boot(first, 0)
            if vol is None:
                # 부트 섹터가 지워진 경우: NTFS 는 볼륨의 마지막 섹터에 같은 부트 섹터를 둔다.
                # 백업에 적힌 볼륨 크기가 이 자리의 크기와 맞을 때만 믿는다 (이미지 끝의 백업이 다른 파티션의 것일 수 있다)
                end = min(start + length, size)
                f.seek(end - SECTOR)
                vol = _boot(f.read(512), start, backup=True)
                if vol is not None and (vol.total_sectors + 1) * vol.bps != end - start:
                    vol = None
            if vol is not None and all(v.offset != vol.offset for v in found):
                found.append(vol)
    return found


def looks_like_disk(path: str) -> bool:
    try:
        return bool(find_volumes(path))
    except (OSError, struct.error):
        return False


def _fixup(rec: bytearray, bps: int) -> bool:
    """MFT 레코드의 섹터 끝 2바이트를 원래 값으로 되돌린다 (update sequence). 맞지 않으면 False."""
    usa_off, usa_n = struct.unpack_from("<HH", rec, 4)
    if usa_n < 1 or usa_off + 2 * usa_n > len(rec):
        return False
    check = rec[usa_off:usa_off + 2]
    for i in range(1, usa_n):
        end = i * bps
        if end > len(rec):
            break
        if rec[end - 2:end] != check:
            return False
        rec[end - 2:end] = rec[usa_off + 2 * i:usa_off + 2 * i + 2]
    return True


def _runs(data: bytes, off: int) -> list[tuple[int | None, int]]:
    """데이터 위치 목록(runlist) → [(시작 클러스터 또는 None(빈 곳), 클러스터 수)]."""
    runs, lcn = [], 0
    while off < len(data) and data[off]:
        head = data[off]
        ln, lo = head & 0xF, head >> 4
        if ln == 0 or off + 1 + ln + lo > len(data):
            break
        count = int.from_bytes(data[off + 1:off + 1 + ln], "little")
        if lo:
            lcn += int.from_bytes(data[off + 1 + ln:off + 1 + ln + lo], "little", signed=True)
            runs.append((lcn, count))
        else:
            runs.append((None, count))
        off += 1 + ln + lo
    return runs


@dataclass
class Stream:
    name: str                       # "" 은 본 데이터, 아니면 ADS 이름
    resident: bytes | None = None
    runs: list = field(default_factory=list)
    vcn: int = 0
    size: int = 0
    alloc: int = 0


@dataclass
class Record:
    number: int
    in_use: bool
    directory: bool
    name: str = ""
    parent: int = -1
    streams: dict = field(default_factory=dict)


def _parse_record(raw: bytes, number: int, bps: int) -> Record | None:
    rec = bytearray(raw)
    if rec[:4] != b"FILE" or not _fixup(rec, bps):
        return None
    flags, = struct.unpack_from("<H", rec, 0x16)
    base_ref, = struct.unpack_from("<Q", rec, 0x20)
    if base_ref & 0xFFFFFFFFFFFF:
        return None          # 다른 레코드에 딸린 확장 레코드
    out = Record(number, bool(flags & 1), bool(flags & 2))
    off, = struct.unpack_from("<H", rec, 0x14)
    best_ns = 99
    while off + 16 <= len(rec):
        atype, alen = struct.unpack_from("<II", rec, off)
        if atype == 0xFFFFFFFF or alen < 16 or off + alen > len(rec):
            break
        nonres, name_len = rec[off + 8], rec[off + 9]
        name_off, = struct.unpack_from("<H", rec, off + 10)
        aname = rec[off + name_off:off + name_off + 2 * name_len].decode("utf-16le", "replace")
        if not nonres:
            clen, coff = struct.unpack_from("<IH", rec, off + 0x10)
            content = bytes(rec[off + coff:off + coff + clen])
            if atype == 0x30 and len(content) >= 0x42:
                parent = int.from_bytes(content[:6], "little")
                nlen, ns = content[0x40], content[0x41]
                fname = content[0x42:0x42 + 2 * nlen].decode("utf-16le", "replace")
                # 이름 공간: 1 Win32, 3 Win32&DOS, 0 POSIX, 2 DOS(8.3). 긴 이름을 고른다
                rank = {1: 0, 3: 0, 0: 1, 2: 2}.get(ns, 3)
                if rank < best_ns:
                    best_ns, out.name, out.parent = rank, fname, parent
            elif atype == 0x80:
                out.streams[aname] = Stream(aname, resident=content, size=len(content), alloc=len(content))
        elif atype == 0x80:
            start_vcn, = struct.unpack_from("<Q", rec, off + 0x10)
            run_off, = struct.unpack_from("<H", rec, off + 0x20)
            alloc, real = struct.unpack_from("<QQ", rec, off + 0x28)
            runs = _runs(bytes(rec[off:off + alen]), run_off)
            s = out.streams.get(aname)
            if s is None or s.resident is not None:
                s = out.streams[aname] = Stream(aname, vcn=start_vcn)
            if start_vcn == 0:
                s.size, s.alloc = real, alloc
            s.runs += runs
        off += alen
    return out


class Ntfs:
    """NTFS 볼륨 하나를 읽는다. f 는 이미지 파일 객체 (seek·read)."""

    def __init__(self, f, vol: Volume, image_size: int):
        self.f, self.vol, self.image_size = f, vol, image_size
        self.notes: list[str] = []
        boot = self.records_at(vol.mft_lcn * vol.cluster, 1)
        mft = boot[0] if boot else None
        if mft is None or "" not in mft.streams:
            raise DiskError("MFT 의 첫 레코드($MFT)를 읽지 못했습니다")
        self.mft_runs = mft.streams[""].runs
        self.mft_size = mft.streams[""].size

    def read(self, off: int, n: int) -> bytes:
        if off < 0 or n <= 0:
            return b""
        self.f.seek(self.vol.offset + off)
        return self.f.read(n)

    def records_at(self, off: int, count: int) -> list[Record | None]:
        size = self.vol.record
        raw = self.read(off, size * count)
        return [_parse_record(raw[i * size:(i + 1) * size], -1, self.vol.bps) for i in range(len(raw) // size)]

    def records(self):
        """MFT 의 모든 레코드 (번호가 매겨진 Record). 상한 MAX_RECORDS."""
        number = 0
        size, cl = self.vol.record, self.vol.cluster
        total = min(self.mft_size // size, MAX_RECORDS)
        for lcn, count in self.mft_runs:
            if lcn is None:
                number += count * cl // size
                continue
            for i in range(count * cl // size):
                if number >= total:
                    return
                rec = _parse_record(self.read(lcn * cl + i * size, size), number, self.vol.bps)
                if rec is not None:
                    rec.number = number
                    yield rec
                number += 1

    def data(self, s: Stream, limit: int) -> bytes:
        """스트림 내용 (limit 바이트까지). 빈 곳(sparse)은 0."""
        if s.resident is not None:
            return s.resident[:limit]
        want = min(s.size, limit)
        out = bytearray()
        cl = self.vol.cluster
        for lcn, count in s.runs:
            if len(out) >= want:
                break
            n = min(count * cl, want - len(out))
            if lcn is None:
                out += bytes(n)
            else:
                chunk = self.read(lcn * cl, n)
                out += chunk + bytes(n - len(chunk))
        return bytes(out[:want])

    def bitmap(self, records: dict) -> bytes | None:
        rec = records.get(6)
        if rec is None or "" not in rec.streams:
            return None
        return self.data(rec.streams[""], 64 << 20)

    def unallocated_runs(self, bitmap: bytes) -> list[tuple[int, int]]:
        """미할당인데 데이터가 있는 클러스터 덩어리 [(시작, 끝)]. 한 바이트로만 채운 클러스터는 빈 것으로 본다."""
        cl = self.vol.cluster
        n = min(len(bitmap) * 8, self.vol.size // cl)
        runs, cur = [], None
        for c in range(n):
            if bitmap[c >> 3] >> (c & 7) & 1:
                cur = None
                continue
            blk = self.read(c * cl, cl)
            if not blk or blk.count(blk[:1]) == len(blk):
                cur = None
                continue
            if cur is not None and cur[1] == c:
                cur[1] = c + 1
            else:
                cur = [c, c + 1]
                runs.append(cur)
        return [tuple(r) for r in runs]


def _path(records: dict, rec: Record) -> tuple[str, bool]:
    """(경로, 부모를 끝까지 찾았나). 루트(5)에 닿으면 True."""
    parts, seen, cur = [rec.name], {rec.number}, rec
    while cur.parent != 5:
        parent = records.get(cur.parent)
        if parent is None or parent.number in seen or not parent.directory:
            return "/".join(reversed(parts)), False
        seen.add(parent.number)
        parts.append(parent.name)
        cur = parent
    return "/".join(reversed(parts)), True


def _safe(name: str) -> str:
    return _BAD_NAME.sub("_", name).strip(" .") or "_"


@dataclass
class Item:
    rel: str            # 풀 폴더 기준 경로
    data: bytes
    note: str = ""


def ntfs_items(path: str, file_limit: int, total_limit: int, notes: list):
    """이미지 안 NTFS 볼륨의 파일·지운 파일·ADS·미할당 덩어리를 하나씩 낸다 (Item). 요약 문장은 notes 에 더한다."""
    vols = find_volumes(path)
    size = os.path.getsize(path)
    budget = total_limit
    with open(path, "rb") as f:
        for vi, vol in enumerate(vols):
            prefix = f"vol{vi + 1}/" if len(vols) > 1 else ""
            fs = Ntfs(f, vol, size)
            head = f"볼륨 {vi + 1} ({vol.offset} 바이트부터): " if len(vols) > 1 else ""
            if vol.backup:
                notes.append(head + "부트 섹터가 망가져 있어 볼륨 끝의 백업 부트 섹터로 읽음")
            records = {r.number: r for r in fs.records()}
            live = deleted = ads = 0
            lost = []        # 위치 정보가 없는 지운 파일 (이름, 할당 클러스터 수)
            for rec in sorted(records.values(), key=lambda r: r.number):
                if rec.number < FIRST_USER_RECORD or rec.directory or not rec.name:
                    continue
                rel, rooted = _path(records, rec)
                if rel.startswith("$Extend/") or (rooted and rel.startswith("$") and "/" not in rel):
                    continue
                rel = "/".join(_safe(p) for p in rel.split("/"))
                if not rec.in_use:
                    rel = "_deleted/" + rel
                elif not rooted:
                    rel = "_orphan/" + rel
                for sname, s in rec.streams.items():
                    target = rel if not sname else f"{rel}~{_safe(sname)}"
                    if not rec.in_use and s.resident is None and not s.runs:
                        lost.append((rec.name, -(-s.alloc // vol.cluster) if s.alloc else 0))
                        continue
                    if budget <= 0:
                        break
                    data = fs.data(s, min(file_limit, budget))
                    budget -= len(data)
                    note = ""
                    if not rec.in_use:
                        deleted += 1
                        note = "지운 파일 (내용이 다른 파일로 덮였을 수 있음)" if s.resident is None else "지운 파일"
                    elif sname:
                        ads += 1
                        note = f"ADS(이름 붙은 데이터 스트림) {sname}"
                    else:
                        live += 1
                    if s.size > len(data):
                        note = (note + ", " if note else "") + f"앞 {len(data)} 바이트만 (크기 {s.size})"
                    yield Item(prefix + target, data, note)
            summary = f"파일 {live}개"
            if deleted:
                summary += f", 지운 파일 {deleted}개"
            if ads:
                summary += f", ADS {ads}개"
            notes.append(head + summary)
            if lost:
                desc = ", ".join(f"{n}({c}클러스터)" for n, c in lost[:8])
                notes.append(f"위치 정보가 지워진 지운 파일 {len(lost)}개: {desc}")

            bitmap = fs.bitmap(records)
            runs = fs.unallocated_runs(bitmap) if bitmap is not None else []
            taken = 0
            for start, end in runs[:MAX_UNALLOC_RUNS]:
                n = min((end - start) * vol.cluster, MAX_UNALLOC_RUN, MAX_UNALLOC_TOTAL - taken, budget)
                if n <= 0:
                    break
                data = fs.read(start * vol.cluster, n)
                taken += len(data)
                budget -= len(data)
                same = [nm for nm, c in lost if c == end - start]
                note = f"미할당 클러스터 {start}~{end - 1} ({end - start}개)"
                if same:
                    note += f", 지운 {'·'.join(same[:3])} 의 할당 크기와 같음"
                yield Item(f"{prefix}_unallocated/clusters_{start}-{end - 1}.bin", data, note)
            joined = _join_lost(lost, runs)
            if joined and budget > 0:
                data = b"".join(fs.read(s * vol.cluster, (e - s) * vol.cluster) for _, s, e in joined)[:budget]
                budget -= len(data)
                names = "+".join(n for n, _, _ in joined)
                yield Item(f"{prefix}_unallocated/joined_{_safe(names)[:80]}.bin", data,
                           f"추정: 지운 {names} 를 크기가 같은 미할당 덩어리로 이름 순서대로 이어 붙임 (확인 필요)")
            if runs:
                more = f" (앞 {MAX_UNALLOC_RUNS}개만)" if len(runs) > MAX_UNALLOC_RUNS else ""
                notes.append(f"미할당 영역의 데이터 덩어리 {len(runs)}개{more} → _unallocated/ (지운 파일 내용일 수 있음)")
            if budget <= 0:
                notes.append("전체 크기 상한에 걸려 나머지는 꺼내지 않음")


def _natural(name: str):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", name)]


def _join_lost(lost, runs) -> list[tuple[str, int, int]] | None:
    """위치 정보가 지워진 지운 파일 2개 이상이 모두 크기(클러스터 수)가 같은 미할당 덩어리와 하나씩만 맞으면
    [(이름, 시작, 끝)] 을 이름 순서로. 하나라도 짝이 없거나 둘 이상이면 None (추측하지 않는다)."""
    if len(lost) < 2:
        return None
    pairs, used = [], set()
    for name, clusters in sorted(lost, key=lambda x: _natural(x[0])):
        match = [r for r in runs if r[1] - r[0] == clusters]
        if clusters == 0 or len(match) != 1 or match[0] in used:
            return None
        used.add(match[0])
        pairs.append((name, *match[0]))
    return pairs


def ntfs_longest_name(path: str) -> int:
    try:
        vols = find_volumes(path)
        if not vols:
            return 0
        with open(path, "rb") as f:
            fs = Ntfs(f, vols[0], os.path.getsize(path))
            records = {r.number: r for r in fs.records()}
        return max((len(_path(records, r)[0]) + 12 for r in records.values() if r.name), default=0)
    except (OSError, DiskError, struct.error):
        return 0


# ---------------------------------------------------------------- 7비트로 압축한 글자

def find_7bit(data: bytes, prefixes, pattern, limit: int = 20) -> list[tuple[int, bytes]]:
    """7비트로 압축한 글자(ESE 데이터베이스의 짧은 글자, SMS PDU 등) 속 플래그를 찾는다.

    글자 하나를 7비트로, 작은 비트부터 이어 붙인다. 플래그 접두사(DH{ 등)를 그렇게 놓으면 시작 비트가 바이트 안의
    어디냐(8가지)에 따라 바이트 모양이 정해진다. 위치마다 접두사 비트로 완전히 정해지는 바이트를 bytes.find 로 찾고,
    경계에 걸친 나머지 비트를 정수로 맞춰 본 뒤, 7비트씩 풀어 pattern 에 맞는지 본다. [(바이트 위치, 플래그)]
    """
    from ctfkit.flags import flag_quality

    found, seen = [], set()
    for prefix in prefixes:
        lit = (prefix + "{").encode()
        bits = 0
        for i, ch in enumerate(lit):
            bits |= (ch & 0x7F) << (7 * i)
        nbits = 7 * len(lit)
        for shift in range(8):
            first = (shift + 7) // 8                     # 완전히 정해지는 첫 바이트 (접두사 시작 바이트 기준)
            last = (shift + nbits) // 8                  # 그 다음 (포함 안 함)
            span = (shift + nbits + 7) // 8              # 접두사가 걸치는 바이트 수
            key = bytes(((bits << shift) >> (8 * k)) & 0xFF for k in range(first, last))
            mask = ((1 << nbits) - 1) << shift
            pos = data.find(key)
            while pos != -1:
                if len(found) >= limit:
                    return found
                base = pos - first
                if base >= 0 and int.from_bytes(data[base:base + span], "little") & mask == bits << shift:
                    start_bit = base * 8 + shift
                else:
                    pos = data.find(key, pos + 1)
                    continue
                pos = data.find(key, pos + 1)
                flag = _decode_7bit(data, start_bit, 260)
                fm = pattern.match(flag)
                # 7비트로 읽으면 무작위 바이트도 짧은 플래그 모양이 된다 (평가용 ESE 파일에서 'DH{w;}', 잡음 4MB 에서
                # "DH{0'yWD}"). 괄호 안이 8글자 이상이고 대부분 영숫자·밑줄인 것만 받는다
                if fm and len(fm.group(0)) - len(lit) - 1 >= 8 and flag_quality(fm.group(0)) >= 0.85 \
                        and fm.group(0) not in seen:
                    seen.add(fm.group(0))
                    found.append((start_bit // 8, fm.group(0)))
    return found


def _decode_7bit(data: bytes, start_bit: int, count: int) -> bytes:
    end = min(len(data), (start_bit + 7 * count) // 8 + 2)
    lo = start_bit // 8
    n = int.from_bytes(data[lo:end], "little") >> (start_bit - lo * 8)
    out = bytearray()
    for _ in range(count):
        ch = n & 0x7F
        if not 0x20 <= ch <= 0x7E:
            break
        out.append(ch)
        n >>= 7
    return bytes(out)


def pack_7bit(text: bytes) -> bytes:
    """시험용: 글자를 7비트로 압축한다 (작은 비트부터)."""
    n = 0
    for i, ch in enumerate(text):
        n |= (ch & 0x7F) << (7 * i)
    return n.to_bytes((7 * len(text) + 7) // 8, "little")

