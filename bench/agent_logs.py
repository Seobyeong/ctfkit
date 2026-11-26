"""에이전트 벤치마크의 실행 기록(stream.jsonl)에서 토큰과 왕복이 어디에 쓰였는지 집계한다.

agent.py 는 실행마다 작업 폴더에 stream.jsonl 을 남긴다 (저장소에는 넣지 않음). 이 스크립트는 그 폴더들을 읽어
도구 호출을 분류하고, 실제 토큰으로 비용이 어디에 쓰였는지 나눈다 (cost_breakdown). 오류 난 호출은 원인별로 센다.
명령 내용과 플래그는 출력하지 않는다.

비용 나누기: 왕복마다 새로 캐시에 쓰인 토큰(cache_creation)은 직전 왕복 이후 붙은 내용(에이전트가 쓴 것 + 도구 결과)이다.
이것을 글자 수 비율로 나눠 분류에 준다. 한 번 쓰이고(쓰기 단가) 이후 왕복마다 다시 읽힌다(읽기 단가).
첫 왕복의 캐시 읽기·쓰기는 시스템 프롬프트·과제 지시라 "고정" 이다. 출력은 result 의 합계를 쓴다 (왕복별 값은 스트림에서 부정확).
단가 비율은 실행 기록 138개(Sonnet 5.5)의 실제 비용에서 역산했다 (입력 2 : 쓰기 4 : 읽기 0.1 : 출력 10, 오차 0).
모델마다 단가가 달라도 비율이 크게 다르지 않다고 보고, 마지막에 실제 비용에 맞춰 늘이거나 줄인다.

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


# 단가 비율 (입력 = 2). 실제 비용 138개에서 역산한 값
PRICE = {"input": 2.0, "write": 4.0, "read": 0.1, "output": 10.0}
FIXED = "고정 (시스템 프롬프트·과제 지시)"
OUTPUT = "출력 (생각·스크립트·말)"
WRITTEN = "에이전트가 쓴 것 (다시 읽힘)"
# 보고서에 쓰는 큰 분류. 도구 결과는 분류(category)에 따라 묶는다
COARSE = {"ctfkit start": "ctfkit 출력", "ctfkit 다른 명령": "ctfkit 출력", "AGENTS.md 읽기": "ctfkit 출력",
          "파일 읽기 (cat/Read/head)": "직접 탐색·파일 읽기", "탐색 (ls/file/xxd/strings 등)": "직접 탐색·파일 읽기",
          "환경 찾기 (python 위치 등)": "환경 찾기"}
PARTS = [FIXED, OUTPUT, "ctfkit 출력", "직접 탐색·파일 읽기", "실행 결과", "환경 찾기", WRITTEN]


def coarse(name: str) -> str:
    if name in (FIXED, OUTPUT, WRITTEN):
        return name
    return COARSE.get(name.removeprefix("결과: "), "실행 결과")


def cost_breakdown(stdout: str) -> dict:
    """stream-json 출력 → {분류: USD}. 합계는 실제 비용과 같다. 결과가 없으면 빈 dict."""
    turns, pending, tools, seen, final = [], [], {}, set(), None
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        kind = event.get("type")
        if kind == "assistant":
            message = event.get("message", {})
            if message.get("id") not in seen:
                seen.add(message.get("id"))
                turns.append((message.get("usage", {}), pending))
                pending = []
            for item in message.get("content", []):
                if item.get("type") == "tool_use":
                    data = item.get("input", {})
                    command = data.get("command") or data.get("file_path") or data.get("pattern") or ""
                    tools[item.get("id")] = category(command, item.get("name"))
                pending.append((WRITTEN, len(json.dumps(item, ensure_ascii=False))))
        elif kind == "user" and isinstance(event.get("message", {}).get("content"), list):
            for item in event["message"]["content"]:
                if item.get("type") == "tool_result":
                    content = item.get("content")
                    if isinstance(content, list):
                        content = "".join(x.get("text", "") for x in content if isinstance(x, dict))
                    pending.append(("결과: " + tools.get(item.get("tool_use_id"), "기타"), len(content or "")))
        elif kind == "result":
            final = event
    if not final or not turns:
        return {}
    parts = defaultdict(float)
    n = len(turns)
    for i, (usage, blocks) in enumerate(turns):
        new = usage.get("cache_creation_input_tokens", 0)
        each = PRICE["write"] + PRICE["read"] * (n - i - 1)   # 한 번 쓰이고, 이후 왕복마다 다시 읽힌다
        parts[FIXED] += usage.get("input_tokens", 0) * PRICE["input"]
        if i == 0:
            parts[FIXED] += usage.get("cache_read_input_tokens", 0) * PRICE["read"] * n + new * each
            continue
        total = sum(size for _, size in blocks)
        if not total:
            parts[FIXED] += new * each
            continue
        for name, size in blocks:
            parts[name] += new * size / total * each
    parts[OUTPUT] += (final.get("usage") or {}).get("output_tokens", 0) * PRICE["output"]
    actual = final.get("total_cost_usd") or 0
    scale = actual / sum(parts.values()) if sum(parts.values()) else 0
    return {name: value * scale for name, value in parts.items()}


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
    costs = defaultdict(lambda: defaultdict(float))
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
            for name, usd in cost_breakdown(stream.read_text(encoding="utf-8", errors="replace")).items():
                costs[group][name] += usd
            usage = (final or {}).get("usage", {})
            runs[group].append({"calls": len(rows), "turns": (final or {}).get("num_turns") or 0,
                                "cost": (final or {}).get("total_cost_usd") or 0, "output": usage.get("output_tokens", 0),
                                "errors": sum(1 for r in rows if r[3])})
            for cat, written, size, error in rows:
                d = calls[group, cat]
                d["n"] += 1
                d["written"] += written
                d["size"] += size
                if error:
                    errors[group, error] += 1
    for group in sorted(runs):
        rs, k = runs[group], len(runs[group])
        print(f"\n## {group[0]} 문제, 조건 {group[1]} (실행 {k}개)")
        print(f"실행당: 도구 호출 {sum(r['calls'] for r in rs) / k:.1f}, 왕복 {sum(r['turns'] for r in rs) / k:.1f}, "
              f"비용 ${sum(r['cost'] for r in rs) / k:.4f}, 출력 토큰 {sum(r['output'] for r in rs) / k:.0f}, "
              f"오류 난 호출 {sum(r['errors'] for r in rs) / k:.2f}")
        cost = costs[group]
        total = sum(cost.values()) or 1
        print("| 비용이 쓰인 곳 | 실행당 USD | 비중 |")
        print("| --- | --- | --- |")
        for name, usd in sorted(cost.items(), key=lambda x: -x[1]):
            print(f"| {name} | {usd / k:.4f} | {usd / total * 100:.0f}% |")
        cats = sorted((c for g, c in calls if g == group), key=lambda c: -calls[group, c]["size"])
        print()
        print("| 도구 호출 분류 | 실행당 호출 | 실행당 작성 글자 | 실행당 결과 글자 |")
        print("| --- | --- | --- | --- |")
        for c in cats:
            d = calls[group, c]
            print(f"| {c} | {d['n'] / k:.2f} | {d['written'] / k:.0f} | {d['size'] / k:.0f} |")
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
