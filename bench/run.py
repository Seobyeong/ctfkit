"""벤치마크 실행기: 같은 과제를 표준 라이브러리 코드와 ctfkit 명령으로 풀고 비용을 비교한다.

    python bench/run.py                 # 표를 화면에 출력
    python bench/run.py --write         # bench/RESULTS.md 와 bench/history/v<버전>.md 로 저장
    python bench/run.py --repeat 5      # 실행 시간을 5번 재서 중앙값 사용

과제마다 재는 값:
  - 호출 수   : 명령을 몇 번 실행했는가 (에이전트의 왕복 횟수)
  - 작성 토큰 : 에이전트가 써야 하는 명령·코드의 양 (모델이 생성하는 쪽이라 느리고 비싸다)
  - 읽기 토큰 : 에이전트가 읽어야 하는 결과(stdout + stderr)의 양
  - 실행 시간 : 명령이 도는 데 걸린 시간 (모델이 생각하는 시간은 포함하지 않는다)

토큰은 실제 토크나이저가 아니라 UTF-8 바이트 수 / 4 로 추정한다.
"""

import argparse
import math
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench.tasks import Task, build  # noqa: E402
from ctfkit import __version__  # noqa: E402


def tokens(text: str) -> int:
    return math.ceil(len(text.encode("utf-8")) / 4)


def run_steps(steps, cwd: Path) -> dict:
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONPATH=str(ROOT))
    tok_in = tok_out = 0
    elapsed = 0.0
    last = ""
    for step in steps:
        start = time.perf_counter()
        proc = subprocess.run(step.argv, cwd=cwd, env=env, capture_output=True, timeout=120)
        elapsed += time.perf_counter() - start
        last = proc.stdout.decode("utf-8", errors="replace")
        tok_in += tokens(step.shown)
        tok_out += tokens(last) + tokens(proc.stderr.decode("utf-8", errors="replace"))
    return {"calls": len(steps), "in": tok_in, "out": tok_out, "time": elapsed, "stdout": last}


def measure(task: Task, cwd: Path, repeat: int) -> dict:
    row = {}
    for side in ("baseline", "ctfkit"):
        runs = [run_steps(getattr(task, side), cwd) for _ in range(repeat)]
        best = runs[0]
        best["time"] = statistics.median(r["time"] for r in runs)
        best["ok"] = task.check(best["stdout"])
        best["total"] = best["in"] + best["out"]
        row[side] = best
    return row


def change(before: float, after: float) -> str:
    if before == 0:
        return "-"
    pct = (after - before) / before * 100
    return f"{pct:+.0f}%"


def render(tasks, rows, repeat: int) -> str:
    lines = [
        "# 벤치마크 결과",
        "",
        f"- ctfkit {__version__} · Python {platform.python_version()} · {platform.system()}",
        f"- 실행 시간은 {repeat}회 중앙값. 기기마다 다르므로 절댓값보다 비율을 본다.",
        "- 토큰은 UTF-8 바이트 수 / 4 로 추정한 값이다. 측정 방법과 한계는 [README.md](README.md) 참고.",
        "- 이 파일은 `python bench/run.py --write` 가 만든다. 직접 고치지 않는다.",
        "",
        "| 과제 | 호출 수 | 작성 토큰 | 읽기 토큰 | 합계 토큰 | 변화 | 실행 시간(초) | 정답 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    sums = {s: {"calls": 0, "in": 0, "out": 0, "total": 0, "time": 0.0} for s in ("baseline", "ctfkit")}
    for task, row in zip(tasks, rows):
        b, k = row["baseline"], row["ctfkit"]
        for side, r in row.items():
            for key in sums[side]:
                sums[side][key] += r[key]
        ok = ("O" if b["ok"] else "X") + " / " + ("O" if k["ok"] else "X")
        lines.append(
            f"| {task.title} | {b['calls']} → {k['calls']} | {b['in']} → {k['in']} "
            f"| {b['out']} → {k['out']} | {b['total']} → {k['total']} "
            f"| {change(b['total'], k['total'])} | {b['time']:.2f} → {k['time']:.2f} | {ok} |"
        )
    b, k = sums["baseline"], sums["ctfkit"]
    lines.append(
        f"| **합계** | {b['calls']} → {k['calls']} | {b['in']} → {k['in']} | {b['out']} → {k['out']} "
        f"| {b['total']} → {k['total']} | {change(b['total'], k['total'])} "
        f"| {b['time']:.2f} → {k['time']:.2f} | |"
    )
    lines += ["", "각 칸은 `표준 라이브러리 → ctfkit` 순서다. 정답 칸의 X 는 그 방법이 답을 내지 못했다는 뜻이다.", ""]
    return "\n".join(lines)


def used_commands(tasks) -> list[tuple[str, str | None]]:
    """과제의 ctfkit 풀이가 쓰는 (명령, 하위 명령) 목록. 나온 순서대로, 중복 없이."""
    from ctfkit.cli import build_parser
    from ctfkit.gui.schema import _sub_action

    top = _sub_action(build_parser()).choices
    seen = []
    for task in tasks:
        for step in task.ctfkit:
            args = [a for a in step.argv[step.argv.index("ctfkit") + 1:] if a != "-q"] if "ctfkit" in step.argv else []
            if not args or args[0] not in top:
                continue
            sub = _sub_action(top[args[0]])
            pair = (args[0], args[1] if sub is not None and len(args) > 1 and args[1] in sub.choices else None)
            if pair not in seen:
                seen.append(pair)
    return seen


def discovery(tasks) -> dict:
    """처음 보는 도구에서 쓸 명령을 찾는 비용: -h 를 따라 내려가는 방법과 guide 한 번을 비교한다.

    -h 경로는 `ctfkit -h` 한 번, 쓰는 명령마다 `ctfkit CMD -h`, 하위 명령이 있으면 `ctfkit CMD SUB -h` 를 읽는다.
    """
    def cost(arg_lists):
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONPATH=str(ROOT))
        read = written = 0
        for args in arg_lists:
            proc = subprocess.run([sys.executable, "-m", "ctfkit", *args], env=env, capture_output=True, timeout=60)
            read += tokens(proc.stdout.decode("utf-8", "replace")) + tokens(proc.stderr.decode("utf-8", "replace"))
            written += tokens("ctfkit " + " ".join(args))
        return {"calls": len(arg_lists), "in": written, "out": read, "total": written + read}

    pairs = used_commands(tasks)
    helps = [["-h"]]
    for command in dict.fromkeys(c for c, _ in pairs):
        helps.append([command, "-h"])
    helps += [[c, s, "-h"] for c, s in pairs if s]
    return {"help": cost(helps), "guide": cost([["guide"]]), "commands": len(pairs)}


def render_discovery(d: dict) -> str:
    h, g = d["help"], d["guide"]
    return "\n".join([
        "## 명령을 찾는 비용",
        "",
        f"처음 보는 도구에서 위 과제에 쓰는 명령 {d['commands']}개를 찾는 데 드는 비용이다.",
        "`-h` 경로는 `ctfkit -h`, 명령마다 `ctfkit CMD -h`, 하위 명령마다 `ctfkit CMD SUB -h` 를 읽는다고 본다.",
        "",
        "| 방법 | 호출 수 | 작성 토큰 | 읽기 토큰 | 합계 토큰 |",
        "| --- | --- | --- | --- | --- |",
        f"| `-h` 를 따라 내려가기 | {h['calls']} | {h['in']} | {h['out']} | {h['total']} |",
        f"| `ctfkit guide` 한 번 | {g['calls']} | {g['in']} | {g['out']} | {g['total']} |",
        f"| 변화 | {change(h['calls'], g['calls'])} | | | {change(h['total'], g['total'])} |",
        "",
        "실제 에이전트는 필요한 `-h` 만 읽으므로 이 값은 상한에 가깝다. guide 만으로 옵션이 부족하면 `-h` 를 더 읽어야 한다.",
        "",
    ])


def main() -> int:
    ap = argparse.ArgumentParser(description="ctfkit 토큰·시간 벤치마크")
    ap.add_argument("--write", action="store_true", help="bench/RESULTS.md 로 저장")
    ap.add_argument("--repeat", type=int, default=3, help="실행 시간 측정 반복 횟수 (기본 3)")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        tasks = build(work)
        rows = [measure(t, work, max(1, args.repeat)) for t in tasks]
        found = discovery(tasks)

    text = render(tasks, rows, max(1, args.repeat)) + "\n" + render_discovery(found)
    if args.write:
        (ROOT / "bench" / "RESULTS.md").write_text(text, encoding="utf-8")
        # 버전별 기록을 남겨 "개선 전 → 후" 를 나중에 비교할 수 있게 한다
        history = ROOT / "bench" / "history"
        history.mkdir(exist_ok=True)
        (history / f"v{__version__}.md").write_text(text, encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(text)
    failed = [t.id for t, r in zip(tasks, rows) if not (r["baseline"]["ok"] and r["ctfkit"]["ok"])]
    if failed:
        print("정답을 내지 못한 과제: " + ", ".join(failed), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
