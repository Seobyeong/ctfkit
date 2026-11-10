"""벤치마크 과제가 유효한지 검사한다: 두 풀이 방법 모두 정답을 내야 비교가 의미 있다."""

from bench.run import measure
from bench.tasks import build


def test_all_tasks_solved_by_both_sides(tmp_path):
    tasks = build(tmp_path)
    assert len(tasks) >= 10
    for task in tasks:
        row = measure(task, tmp_path, repeat=1)
        assert row["baseline"]["ok"], f"{task.id}: 표준 라이브러리 풀이가 정답을 내지 못함"
        assert row["ctfkit"]["ok"], f"{task.id}: ctfkit 풀이가 정답을 내지 못함"
