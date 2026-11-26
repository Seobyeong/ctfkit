"""README 의 예시 명령이 설치된 ctfkit 에서 그대로 동작하는지 확인한다 (v1.0 설치 검증).

    python bench/readme_check.py                      # PATH 의 ctfkit
    python bench/readme_check.py --ctfkit venv/bin/ctfkit

README 에 쓴 입력 파일(chall.zip, memo.png 등)을 임시 폴더에 같은 모양으로 만들고, README 의 명령을 그 폴더에서
실행해 README 에 적은 출력 줄이 나오는지 본다. 저장소를 import 하지 않고 **설치된 실행 파일만** 부른다.
깨끗한 가상환경, 다른 PC, WSL 에서 같은 결과가 나오는지 보는 용도다.

웹 예시(web curl, web fuzz)는 서버가 필요해 제외한다. 외부 도구가 필요한 예시는 그 도구가 있을 때만 확인한다.
"""

import argparse
import base64
import io
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def _png(size: int) -> bytes:
    """size 바이트짜리 PNG 모양 파일 (서명 + IHDR + 채움 + IEND)."""
    ihdr = b"\x00\x00\x00\x0dIHDR" + struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0) + b"\x00" * 4
    iend = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    return PNG_SIG + ihdr + b"\x00" * (size - len(PNG_SIG) - len(ihdr) - len(iend)) + iend


def _elf() -> bytes:
    """보호 기법이 모두 꺼진 최소 x86-64 ELF (프로그램 헤더 2개, 섹션 없음)."""
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8 + struct.pack(
        "<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x400078 + 112, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 300, 300, 0x1000)
    stack = struct.pack("<IIQQQQQQ", 0x6474E551, 7, 0, 0, 0, 0, 0, 0)   # 실행 가능 스택 = NX 꺼짐
    return (ehdr + load + stack + b"\x90" * 64 + b"\xc3").ljust(300, b"\x00")


def make_files(folder: str) -> None:
    def write(name, data):
        with open(os.path.join(folder, name), "wb") as f:
            f.write(data)

    # chall.zip: zip 안의 tar.gz 안에 base64(hex(플래그)) 메모
    memo = base64.b64encode(b"DH{nested_archive_flag}".hex().encode())
    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w:gz") as t:
        for name, data in (("secret/memo.txt", memo), ("secret/pic.png", _png(208))):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr("readme.txt", "find the flag\n")
        z.writestr("data/inner.tar.gz", tbuf.getvalue())
    write("chall.zip", zbuf.getvalue())

    # memo.png: PNG 뒤에 ZIP(memo.txt = base64(플래그))
    mbuf = io.BytesIO()
    with zipfile.ZipFile(mbuf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("memo.txt", base64.b64encode(b"DH{zip_then_base64}") + b"\n")
    write("memo.png", _png(4104) + mbuf.getvalue())
    write("empty.png", _png(308))
    write("app.exe", b"MZ" + b"\x00" * 62 + "DH{wide_string_flag}".encode("utf-16-le") + b"\x00" * 16)
    write("words.txt", b"123456\nqwerty\npassword\nletmein\n")
    write("chall", _elf())
    os.mkdir(os.path.join(folder, "work"))   # start 의 작업 폴더 chall/ 이 바이너리 chall 과 겹치지 않게


# (설명, 인자, stdout 에 있어야 하는 줄들, 필요한 외부 도구)
CASES = [
    ("문제 시작", ["start", "chall.zip", "--root", "work"],
     ["플래그: DH{nested_archive_flag}  [extracted/chall.zip/data/inner.tar.gz.d/secret/memo.txt · 파일 본문 (base64→hex)]",
      "파일 5개 (압축 2개 풂)"], None),
    ("auto", ["auto", "NjY2YzYxNjc3YjY4Njk3ZA=="], ["flag{hi}", "  [2] hex                    -> flag{hi}"], None),
    ("codec", ["codec", "decode", "base64", "ZmxhZ3toZWxsb30="], ["flag{hello}"], None),
    ("triage 플래그", ["triage", "memo.png"],
     ["플래그: DH{zip_then_base64}  [ZIP:memo.txt (base64)]", "숨은 파일: 0x1008 ZIP", "ZIP: memo.txt(29)"], None),
    ("triage 못 찾음", ["triage", "empty.png"],
     ["형식: PNG 이미지 (308 바이트)", "다음: forensic lsb empty.png / forensic strings empty.png --grep <정규식>"], None),
    ("triage UTF-16", ["triage", "app.exe"], ["플래그: DH{wide_string_flag}  [strings -el (UTF-16)]"], "strings"),
    ("doctor", ["doctor"], ["외부 도구 (triage·start 가 있으면 함께 씀)"], None),
    ("carve", ["forensic", "carve", "memo.png"], ["  오프셋 0x1008 (4104)  ZIP"], None),
    ("crack caesar", ["crack", "caesar", "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj", "-n", "2"],
     ["3                   0.62  The quick brown fox jumps over the lazy dog"], None),
    ("hash id", ["hash", "id", "5f4dcc3b5aa765d61d8327deb882cf99"], ["가능한 종류 (3): md5, md4, ntlm"], None),
    ("hash crack", ["hash", "crack", "5f4dcc3b5aa765d61d8327deb882cf99", "-w", "words.txt"],
     ["[+] 찾음: password  (md5, 3개 시도)"], None),
    ("rsa", ["rsa", "decrypt", "-n", "1208925852309707152975447", "-e", "65537", "-c", "298898839777870285982038"],
     ["[+] 분해 성공: 1099511640127 * 1099511645161", "m (bytes) = flag{rsa}"], None),
    ("jwt forge", ["jwt", "forge", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJhZG1pbiI6ZmFsc2V9."
                   "7Mc4Ujc5fz2145BmF6Q2f-zwslS_RkT5Kn_2x6YxWxg", "--alg", "none", "--set", "admin=true"],
     ["eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiZ3Vlc3QiLCJhZG1pbiI6dHJ1ZX0."], None),
    ("cyclic", ["pwn", "cyclic", "-l", "0x61616166"], ["20"], None),
    ("checksec", ["pwn", "checksec", "chall"], [], None),
    ("rev info", ["rev", "info", "chall", "--sections"], [], None),
    ("template pwn", ["template", "pwn", "chall", "--port", "31337"], ["PIE = False", "NX = False"], None),
    ("template rsa", ["template", "rsa", "-n", "1208925852309707152975447", "-e", "3", "-c", "8"], ["e = 3"], None),
    ("guide", ["guide"], ["ctfkit -q CMD ...   stdout=답만. 입력: 인자 | -f FILE | stdin. 세부 옵션: CMD -h"], None),
    ("-q auto", ["-q", "auto", "NjY2YzYxNjc3YjY4Njk3ZA=="], ["flag{hi}"], None),
    ("-q triage", ["-q", "triage", "memo.png"], ["DH{zip_then_base64}"], None),
]


def run(ctfkit: str, folder: str) -> list[tuple[str, str, str]]:
    env = dict(os.environ, PYTHONIOENCODING="utf-8", CTFKIT_CONFIG="none")
    rows = []
    for name, argv, expect, tool in CASES:
        if tool and not shutil.which(tool):
            rows.append((name, "건너뜀", f"{tool} 없음"))
            continue
        proc = subprocess.run([ctfkit, *argv], cwd=folder, env=env, capture_output=True, timeout=120)
        # README 는 화면에 보이는 대로(stdout 과 stderr 안내를 함께) 적었으므로 둘 다 본다
        lines = (proc.stdout + b"\n" + proc.stderr).decode("utf-8", "replace").splitlines()
        missing = [line for line in expect if line not in lines]
        if proc.returncode == 2 or "Traceback" in proc.stderr.decode("utf-8", "replace"):
            rows.append((name, "실패", f"종료 코드 {proc.returncode}: {proc.stderr.decode('utf-8', 'replace')[-200:]}"))
        elif missing:
            rows.append((name, "실패", f"없는 줄: {missing[0]!r}"))
        else:
            rows.append((name, "통과", f"종료 코드 {proc.returncode}"))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="README 예시 명령 확인")
    ap.add_argument("--ctfkit", default=shutil.which("ctfkit"), help="ctfkit 실행 파일 (기본: PATH)")
    args = ap.parse_args()
    if not args.ctfkit:
        print("ctfkit 실행 파일을 찾지 못했습니다. pip install 후 다시 실행하거나 --ctfkit 을 주세요.", file=sys.stderr)
        return 2
    version = subprocess.run([args.ctfkit, "--version"], capture_output=True).stdout.decode().strip()
    with tempfile.TemporaryDirectory() as folder:
        make_files(folder)
        rows = run(args.ctfkit, folder)
    print(f"{version} · Python {sys.version.split()[0]} · {sys.platform}")
    for name, status, detail in rows:
        print(f"  [{status}] {name:<14} {detail}")
    failed = sum(status == "실패" for _, status, _ in rows)
    print(f"통과 {sum(s == '통과' for _, s, _ in rows)} / 실패 {failed} / 건너뜀 {sum(s == '건너뜀' for _, s, _ in rows)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
