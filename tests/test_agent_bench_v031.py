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
    for row in rows:
        row["round"] = "1차"
    text = agent.render(rows)
    assert "| 0.030 → 0.020 | -33% |" in text and "3/3 → 3/3" in text and "## 1차" in text
    second = [dict(r, round="2차", cost_usd=r["cost_usd"] / 2 if r["condition"] == "B" else r["cost_usd"]) for r in rows]
    assert "| 2차 | 1 | 0.030 → 0.010 | -67% |" in agent.render(rows + second)


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


def _zip(path, files):
    import zipfile
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)


def test_real_problems_from_zip_and_folder(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    _zip(real / "aaa.zip", {"prob.py": "print(1)", "out.txt": "x"})
    (real / "aaa.flag").write_text("flag{z}\n", encoding="utf-8")
    (real / "aaa.note").write_text("암호 · 연습\n", encoding="utf-8")
    _zip(real / "bbb.zip", {"a": "b"})                       # 정답 없음 → 건너뜀
    (real / "ccc").mkdir()
    (real / "ccc" / "sub").mkdir()
    (real / "ccc" / "sub" / "x.bin").write_bytes(b"\x00")
    (real / "ccc" / "flag.txt").write_text("DH{y}", encoding="utf-8")
    found, skipped = agent.load_real(real)
    assert len(found) == 2 and len(skipped) == 1 and "bbb.zip" in skipped[0]
    by_note = {p.note: p for p in found.values()}
    zipped = by_note["암호 · 연습"]
    assert zipped.id.startswith("real-") and "aaa" not in zipped.id and "연습" in zipped.title
    chall = tmp_path / "c1"
    chall.mkdir()
    assert zipped.build(chall) == "flag{z}" and (chall / "prob.py").exists()
    chall = tmp_path / "c2"
    chall.mkdir()
    assert by_note[""].build(chall) == "DH{y}"
    assert (chall / "sub" / "x.bin").exists() and not (chall / "flag.txt").exists()
    assert "flag{...}" in agent.prompt("A", "flag") and "DH{...}" in agent.PROMPTS["B"]


def test_real_zip_with_outside_path_is_refused(tmp_path):
    _zip(tmp_path / "evil.zip", {"../escape.txt": "x"})
    import pytest
    with pytest.raises(SystemExit):
        agent._extract(tmp_path / "evil.zip", tmp_path / "out")
    assert not (tmp_path / "escape.txt").exists()


def test_real_rows_keep_only_numbers():
    row = agent.parse(_stream(["cat chall/prob.py", "ctfkit start chall", "python -c 'print(\"DH{q}\")'"], "FLAG: DH{q}"),
                      "real-abc", "B", "sonnet", "DH{q}", 1.0, False, "", "w")
    clean = agent.strip_real(row, "DH{q}")
    assert clean["commands"] == ["Bash", "Bash: ctfkit", "Bash"] and clean["solved"] and clean["valid"]
    assert "DH{q}" not in json.dumps(clean, ensure_ascii=False)
    peek = agent.parse(_stream(["cat ../../bench/real/x.flag"], "FLAG: DH{q}"), "real-abc", "A", "sonnet", "DH{q}",
                       1.0, False, "", "w")
    assert not agent.strip_real(peek, "DH{q}")["valid"]


def test_eval_set_is_measured_once_and_flags_unhelpful_problems():
    rows = [{"problem": "real-a", "set": "eval"}, {"problem": "real-b", "set": "dev"}]
    assert agent.already_evaluated(rows, ["real-a", "real-b", "real-c"]) == ["real-a"]
    runs = []
    for problem, a, b, ok in (("p-help", 0.04, 0.02, True), ("p-cost", 0.03, 0.03, True), ("p-wrong", 0.05, 0.01, False)):
        for cond, cost in (("A", a), ("B", b)):
            row = agent.parse(_stream(["x"], "FLAG: DH{x}" if ok or cond == "A" else "모름", cost), problem, cond,
                              "sonnet", "DH{x}", 1.0, False, "", "w")
            runs.append(row)
    assert agent.move_candidates(runs) == ["p-cost", "p-wrong"]
    commit, dirty = agent.git_state()
    assert commit and isinstance(dirty, bool)


def test_vigenere_evidence_shows_key_and_plaintext(tmp_path):
    """키가 근거에 없으면 에이전트가 키를 직접 다시 구했다 (모의 비즈네르 -6%)."""
    from ctfkit.commands.triage import analyze, compile_pattern

    flag = agent.build_vigenere(tmp_path, random.Random(2026))
    found = {}
    for path in tmp_path.iterdir():
        report = analyze(str(path), compile_pattern(None), use_external=False)
        found.update({f: report.evidence[f] for f, _ in report.flags})
    assert "(vigenere 키 " in found[flag] and "푼 글 앞부분 " in found[flag]


def _usage(write, read=0):
    return {"input_tokens": 2, "cache_creation_input_tokens": write, "cache_read_input_tokens": read, "output_tokens": 5}


def test_cost_parts_split_actual_cost_by_what_entered_context():
    """왕복마다 새로 쓰인 토큰을 그 사이에 붙은 내용에 나눠 준다. 합계는 실제 비용과 같다."""
    events = [
        {"type": "assistant", "message": {"id": "m1", "usage": _usage(3000, 5000), "content": [
            {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "ctfkit start chall"}}]}},
        {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t1", "content": "x" * 4000}]}},
        {"type": "assistant", "message": {"id": "m2", "usage": _usage(1000, 8000), "content": [
            {"type": "tool_use", "id": "t2", "name": "Bash", "input": {"command": "cat chall/a.txt"}}]}},
        {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t2", "content": "y" * 400}]}},
        {"type": "assistant", "message": {"id": "m3", "usage": _usage(200, 9000), "content": [{"type": "text", "text": "끝"}]}},
        {"type": "result", "result": "FLAG: DH{x}", "total_cost_usd": 0.03, "num_turns": 3, "duration_ms": 10,
         "usage": {"input_tokens": 6, "cache_creation_input_tokens": 4200, "cache_read_input_tokens": 22000,
                   "output_tokens": 300}},
    ]
    row = agent.parse("\n".join(json.dumps(e) for e in events), "p", "B", "sonnet", "DH{x}", 1.0, False, "", "w")
    parts = row["cost_parts"]
    assert abs(sum(parts.values()) - 0.03) < 1e-5
    assert parts["ctfkit 출력"] > parts["직접 탐색·파일 읽기"] > 0
    assert parts["고정 (시스템 프롬프트·과제 지시)"] > parts["ctfkit 출력"]
    text = agent.render([dict(row, round="1차")])
    assert "비용이 쓰인 곳" in text and "| ctfkit 출력 | - |" in text


def test_cost_parts_empty_without_result():
    assert agent.parse("", "p", "A", "sonnet", "DH{x}", 1.0, True, "", "w")["cost_parts"] == {}
