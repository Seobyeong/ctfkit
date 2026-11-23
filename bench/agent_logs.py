"""에이전트 벤치마크의 실행 기록(stream.jsonl)에서 토큰과 왕복이 어디에 쓰였는지 집계한다.

agent.py 는 실행마다 작업 폴더에 stream.jsonl 을 남긴다 (저장소에는 넣지 않음). 이 스크립트는 그 폴더들을 읽어
도구 호출을 분류하고, 결과의 크기와 "이후 몇 번 다시 읽혔는가" 를 곱해 재읽기 비중을 낸다. 오류 난 호출은 원인별로 센다.
명령 내용과 플래그는 출력하지 않는다.

  python bench/agent_logs.py <agent.py 의 --workdir 폴더> [...]
"""

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

CATEGORIES = [
    ("ctfkit start", lambda c, t: "ctfkit start" in c),
    ("ctfkit 다른 명령", lambda c, t: re.search(r"(?<![\w/.-])ctfkit\s", c) is not None),
    ("AGENTS.md 읽기", lambda c, t: "AGENTS.md" in c),
    ("환경 찾기 (python 위치 등)", lambda c, t: re.search(r"which |where |Programs/Python|py -0|--version", c) is not None),
    ("스크립트 작성", lambda c, t: t in ("Write", "Edit") or ("<<" in c and re.search(r"cat\s*>", c) is not None)),
    ("python 실행", lambda c, t: "python" in c),
    ("파일 읽기 (cat/Read/head)", lambda c, t: t == "Read" or re.match(r"(cd \S+ *(&&|;) *)?(cat|head|tail)\b", c) is not None),
    ("탐색 (ls/file/xxd/strings 등)", lambda c, t: t in ("Glob", "Grep")
     or re.search(r"\b(ls|file|xxd|od|strings|find|unzip|binwalk|grep)\b", c) is not None),
]


def category(command: str, tool: str) -> str:
    return next((name for name, test in CATEGORIES if test(command, tool)), "기타")


def error_kind(command: str, text: str) -> str:
    if "UnicodeEncodeError" in text or "cp949" in text:
        return "콘솔 인코딩 (cp949)"
    if "Python was not found" in text:
        return "python3 없음 (윈도우 Store 껍데기)"
    if re.search(r"command not found|not recognized", text):
        return "명령 없음 (" + (re.search(r"([\w.-]+): command not found", text) or re.search(r"(\S+)", text)).group(1)[:20] + ")"
    if "ctfkit start" in command:
        return "ctfkit start 종료 코드 1 (플래그 못 찾음)"
    if "SyntaxError" in text or "IndentationError" in text:
        return "스크립트 문법 오류"
    if "Traceback" in text:
        return "스크립트 실행 오류"
    if "No such file" in text or "does not exist" in text:
        return "파일 경로 틀림"
    return "기타 (종료 코드만)"


def read_stream(path: Path):
    """[(분류, 작성 글자, 결과 글자, 오류 종류 또는 None)] 과 마지막 result 이벤트."""
    calls, order, results, final = {}, [], {}, None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        kind = event.get("type")
        if kind == "assistant":
            for item in event.get("message", {}).get("content", []):
                if item.get("type") == "tool_use":
                    data = item.get("input", {})
                    command = data.get("command") or data.get("file_path") or data.get("pattern") or ""
                    calls[item["id"]] = (item.get("name"), command, len(json.dumps(data, ensure_ascii=False)))
                    order.append(item["id"])
        elif kind == "user" and isinstance(event.get("message", {}).get("content"), list):
            for item in event["message"]["content"]:
                if item.get("type") != "tool_result":
                    continue
                content = item.get("content")
                if isinstance(content, list):
                    content = "".join(x.get("text", "") for x in content if isinstance(x, dict))
                content = content or ""
                tool, command, _ = calls.get(item["tool_use_id"], ("", "", 0))
                failed = item.get("is_error") or re.search(r"Traceback|Error:|not found|No such file", content)
                results[item["tool_use_id"]] = (len(content), error_kind(command, content) if failed else None)
        elif kind == "result":
            final = event
    rows = []
    for cid in order:
        tool, command, written = calls[cid]
        size, error = results.get(cid, (0, None))
        rows.append((category(command, tool), written, size, error))
    return rows, final


def main(folders) -> int:
    calls = defaultdict(lambda: defaultdict(float))
    errors = Counter()
    runs = defaultdict(list)
    for folder in folders:
        for stream in Path(folder).rglob("stream.jsonl"):
            m = re.match(r"(.+)-([AB])-", stream.parent.name)
            if not m:
                continue
            problem, cond = m.groups()
            group = ("실제" if problem.startswith("real-") else "모의", cond)
            rows, final = read_stream(stream)
            usage = (final or {}).get("usage", {})
            runs[group].append({"calls": len(rows), "turns": (final or {}).get("num_turns") or 0,
                                "cost": (final or {}).get("total_cost_usd") or 0, "output": usage.get("output_tokens", 0),
                                "errors": sum(1 for r in rows if r[3])})
            for i, (cat, written, size, error) in enumerate(rows):
                d = calls[group, cat]
                d["n"] += 1
                d["written"] += written
                d["size"] += size
                d["carry"] += (written + size) * (len(rows) - i)   # 이후 호출마다 다시 읽힌다
                if error:
                    errors[group, error] += 1
    for group in sorted(runs):
        rs, k = runs[group], len(runs[group])
        print(f"\n## {group[0]} 문제, 조건 {group[1]} (실행 {k}개)")
        print(f"실행당: 도구 호출 {sum(r['calls'] for r in rs) / k:.1f}, 왕복 {sum(r['turns'] for r in rs) / k:.1f}, "
              f"비용 ${sum(r['cost'] for r in rs) / k:.4f}, 출력 토큰 {sum(r['output'] for r in rs) / k:.0f}, "
              f"오류 난 호출 {sum(r['errors'] for r in rs) / k:.2f}")
        cats = sorted((c for g, c in calls if g == group), key=lambda c: -calls[group, c]["carry"])
        total = sum(calls[group, c]["carry"] for c in cats) or 1
        print("| 분류 | 실행당 호출 | 실행당 작성 글자 | 실행당 결과 글자 | 재읽기 비중 |")
        print("| --- | --- | --- | --- | --- |")
        for c in cats:
            d = calls[group, c]
            print(f"| {c} | {d['n'] / k:.2f} | {d['written'] / k:.0f} | {d['size'] / k:.0f} | {d['carry'] / total * 100:.0f}% |")
        kinds = [(e, n) for (g, e), n in errors.most_common() if g == group]
        if kinds:
            print("오류: " + ", ".join(f"{e} {n / k:.2f}" for e, n in kinds) + " (실행당)")
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    raise SystemExit(main(sys.argv[1:]))
