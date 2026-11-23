"""bench/agent.py: 실제 에이전트 벤치마크의 기록 해석과 모의 문제. claude 는 실행하지 않는다."""

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import agent  # noqa: E402
from ctfkit.cli import main  # noqa: E402


def _stream(commands, answer, cost=0.02):
    events = [{"type": "assistant", "message": {"content": [
        {"type": "tool_use", "name": "Bash", "input": {"command": c}} for c in commands]}}]
    events.append({"type": "result", "result": answer, "total_cost_usd": cost, "num_turns": len(commands) + 1,
                   "duration_ms": 1500, "usage": {"input_tokens": 10, "cache_creation_input_tokens": 100,
                                                  "cache_read_input_tokens": 1000, "output_tokens": 50}})
    return "\n".join(json.dumps(e) for e in events)


def test_parse_counts_tokens_and_checks_last_line():
    row = agent.parse(_stream(["ls chall"], "풀었다\nFLAG: DH{x}"), "p", "A", "sonnet", "DH{x}", 2.0, False, "", "w")
    assert row["solved"] and row["valid"] and row["total_tokens"] == 1160 and row["turns"] == 2
    row = agent.parse(_stream([], "DH{x} 인 것 같지만 확실하지 않다\n모르겠다"), "p", "B", "sonnet", "DH{x}", 2.0, False, "", "w")
    assert not row["solved"] and row["flag_anywhere"]


def test_ctfkit_use_in_condition_a_is_invalid_but_paths_are_not_use():
    assert agent.uses_ctfkit(["Bash: ctfkit start chall"])
    assert agent.uses_ctfkit(["Bash: python -m ctfkit guide"])
    assert not agent.uses_ctfkit(["Bash: /tmp/venv-no-ctfkit/Scripts/python -c 1"])
    assert not agent.uses_ctfkit(["Read: ctfkit start chall"])   # 셸 명령만 본다
    row = agent.parse(_stream(["ctfkit start chall"], "FLAG: DH{x}"), "p", "A", "sonnet", "DH{x}", 1.0, False, "", "w")
    assert not row["valid"]


def test_render_uses_medians_and_change():
    rows = []
    for cond, costs in (("A", [0.04, 0.02, 0.03]), ("B", [0.01, 0.02, 0.03])):
        for c in costs:
            row = agent.parse(_stream(["x"], "FLAG: DH{x}", c), "layers", cond, "sonnet", "DH{x}", 1.0, False, "", "w")
            rows.append(row)
    text = agent.render(rows)
    assert "| 0.030 → 0.020 | -33% |" in text and "3/3 → 3/3" in text


def test_every_mock_problem_contains_its_flag_somewhere(tmp_path):
    """모의 문제가 풀 수 있는 모양인지: 플래그가 파일에 그대로 있으면 안 되고(문제가 안 됨), 만들어지기는 해야 한다."""
    for key, (_, build) in agent.PROBLEMS.items():
        chall = tmp_path / key
        chall.mkdir()
        flag = build(chall, random.Random(1))
        assert flag.startswith("DH{")
        blobs = b"".join(p.read_bytes() for p in chall.rglob("*") if p.is_file())
        assert flag.encode() not in blobs, key


def test_ctfkit_solves_rsa_mock_with_evidence(tmp_path, capsys):
    chall = tmp_path / "chall"
    chall.mkdir()
    flag = agent.build_rsa_shared(chall, random.Random(3))
    assert main(["start", str(chall), "--root", str(tmp_path / "ws")]) == 0
    out = capsys.readouterr().out
    assert f"플래그: {flag}" in out and "근거: 다른 n 과 공통 소인수: 성공 (p·q = n 확인" in out
