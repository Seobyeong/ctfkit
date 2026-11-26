"""README 데모 GIF(docs/demo.gif) 만들기.

직접 만든 예제 문제(chall.zip: RSA 소스 + 출력 파일)를 임시 폴더에 만들고,
설치된 ctfkit 으로 실제 명령을 실행해 그 출력을 터미널 모양 GIF 로 그린다.
출력은 손대지 않는다 (실행 결과를 그대로 그림).

    python bench/demo.py            # docs/demo.gif 를 새로 씀
    python bench/demo.py --print    # GIF 없이 출력만 확인

Pillow 가 필요하다 (pip install ".[image]").
"""
from __future__ import annotations

import argparse
import io
import os
import random
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------- 예제 문제

CHALL_PY = '''\
from Crypto.Util.number import getPrime, bytes_to_long

FLAG = open("flag.txt", "rb").read()

p = getPrime(512)
q = next_prime(p)          # 빠르게 두 번째 소수를 고름
n = p * q
e = 65537
c = pow(bytes_to_long(FLAG), e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
'''


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(rng: random.Random, bits: int) -> int:
    while True:
        n = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(n):
            return n


def make_chall(folder: Path) -> Path:
    """chall.zip: 붙어 있는 512비트 소수 두 개로 만든 RSA (소스 + 출력). 항상 같은 값."""
    flag = b"flag{start_to_flag}"
    rng = random.Random(1206)
    p = _prime(rng, 512)
    q = p + 2
    while not _is_prime(q):
        q += 2
    n, e = p * q, 65537
    c = pow(int.from_bytes(flag, "big"), e, n)
    out = f"n = {n}\ne = {e}\nc = {c}\n"
    path = folder / "chall.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("chall/chall.py", CHALL_PY)
        z.writestr("chall/output.txt", out)
    return path


# ---------------------------------------------------------------- 실행

STEPS = [  # (화면에 보일 명령, 실제 인자)
    ("ctfkit start chall.zip", ["start", "chall.zip"]),
    ('ctfkit auto "NjY2YzYxNjc3YjY4Njk3ZA=="', ["auto", "NjY2YzYxNjc3YjY4Njk3ZA=="]),
]


def run_steps(cwd: Path, ctfkit: str) -> list[tuple[str, str]]:
    """명령을 실제로 실행한다. 출력에서 바꾸는 것은 임시 폴더 경로(→ ~/ctf) 하나뿐."""
    env = dict(os.environ, PYTHONIOENCODING="utf-8", NO_COLOR="1", CTFKIT_CONFIG="none")
    for k in ("CLAUDECODE", "AI_AGENT", "CTFKIT_AGENT"):  # 사람용 출력으로
        env.pop(k, None)
    shots = []
    for shown, args in STEPS:
        r = subprocess.run([ctfkit, *args], cwd=cwd, env=env, capture_output=True, text=True,
                           encoding="utf-8", stdin=subprocess.DEVNULL, timeout=120)
        out = (r.stdout + r.stderr).rstrip("\n")
        for p in {str(cwd), str(cwd.resolve())}:
            out = out.replace(p + os.sep, "~/ctf/").replace(p, "~/ctf")
        shots.append((shown, out.replace("\\", "/") if os.sep == "\\" else out))
    return shots


# ---------------------------------------------------------------- 그리기

BG = (30, 31, 36)
FG = (220, 220, 220)
HL = (240, 190, 90)      # [+] 줄
DIM = (140, 140, 150)    # 프롬프트
W, H = 1000, 560
PAD, LINE = 14, 21


def _fonts():
    from PIL import ImageFont
    fonts = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
    mono = ImageFont.truetype(str(fonts / "consola.ttf"), 16)
    kor = ImageFont.truetype(str(fonts / "malgun.ttf"), 15)
    return mono, kor


def _draw_line(draw, x, y, text, color, mono, kor):
    cw = mono.getlength("M")
    cols = int((W - 2 * PAD) // cw)
    col = 0
    for ch in text:
        wide = ord(ch) >= 0x1100
        if col + (2 if wide else 1) > cols - 1:   # 화면보다 긴 줄은 자름
            draw.text((x + col * cw, y), "…", font=mono, fill=DIM)
            break
        font = kor if wide else mono
        draw.text((x + col * cw, y + (1 if wide else 0)), ch, font=font, fill=color)
        col += 2 if wide else 1


def _color(line: str):
    s = line.lstrip()
    if s.startswith(("[+]", "flag{", "플래그:")):
        return HL
    return FG


def render(shots, path: Path, type_ms=45, hold_ms=2200, final_ms=5000):
    from PIL import Image, ImageDraw
    mono, kor = _fonts()
    rows = (H - 2 * PAD) // LINE
    screen: list[tuple[str, tuple]] = []
    frames: list[tuple[Image.Image, int]] = []

    def snap(ms):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        for i, (text, color) in enumerate(screen[-rows:]):
            _draw_line(d, PAD, PAD + i * LINE, text, color, mono, kor)
        frames.append((img, ms))

    for n, (cmd, out) in enumerate(shots):
        if n:
            screen.append(("", FG))
        screen.append(("$ ", DIM))
        snap(600)
        for i in range(0, len(cmd), 2):
            screen[-1] = ("$ " + cmd[: i + 2], FG)
            snap(type_ms)
        snap(400)
        lines = out.splitlines()
        for i, line in enumerate(lines):
            screen.append((line, _color(line)))
            if i % 2 == 1 or i == len(lines) - 1:
                snap(70)
        frames[-1] = (frames[-1][0], final_ms if n == len(shots) - 1 else hold_ms)

    pal = [f[0].quantize(colors=64, method=Image.Quantize.MEDIANCUT) for f in frames]
    buf = io.BytesIO()
    pal[0].save(buf, "GIF", save_all=True, append_images=pal[1:],
                duration=[f[1] for f in frames], loop=0, optimize=True)
    path.write_bytes(buf.getvalue())
    return len(frames), len(buf.getvalue())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--print", action="store_true", help="GIF 없이 출력만")
    ap.add_argument("--out", default=str(ROOT / "docs" / "demo.gif"))
    ap.add_argument("--ctfkit", default="ctfkit", help="실행할 ctfkit (기본: PATH)")
    a = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix="ctfkit-demo-") as tmp:
        make_chall(Path(tmp))
        shots = run_steps(Path(tmp), a.ctfkit)
    for cmd, out in shots:
        print("$ " + cmd)
        print(out)
        print()
    if not a.print:
        n, size = render(shots, Path(a.out))
        print(f"{a.out}: 프레임 {n}개, {size // 1024}KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
