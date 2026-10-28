"""빔 서치(beam search)로 디코딩 경로를 탐색한다.

각 단계에서 현재 후보들에 적용 가능한 모든 변환을 시도하고,
점수가 높은 상위 beam 개만 남겨 다음 단계로 넘어간다.
"""

from collections.abc import Iterator
from dataclasses import dataclass

from ctfkit import registry
from ctfkit.analysis import english_score
from ctfkit.engine.scoring import score
from ctfkit.flags import compile_flag_pattern, find_flag
from ctfkit.registry import TransformError

DEFAULT_DEPTH = 6
DEFAULT_BEAM = 30
# english_score 가 이 이상이면 이미 풀린 평문으로 보고 더 변환하지 않는다.
# 평문에 시저·비즈네르를 또 적용하면 키를 "영어처럼 보이게" 과적합한 쓰레기가 더 높은 점수를 받는다.
SOLVED_THRESHOLD = 0.6
# 최종 순위에서 단계 하나당 깎는 점수. 비슷한 점수면 짧은 경로가 앞선다.
STEP_PENALTY = 0.02
# 키를 추정한 단계는 데이터에 맞춰 고른 것이라 점수가 부풀려지기 쉬워서 더 깎는다.
KEYED_STEP_PENALTY = 0.05


@dataclass(frozen=True)
class Step:
    transform: str
    key: str | None
    output: bytes


@dataclass(frozen=True)
class Result:
    steps: tuple[Step, ...]
    score: float
    flag: bytes | None = None

    @property
    def data(self) -> bytes:
        return self.steps[-1].output

    @property
    def rank_score(self) -> float:
        """최종 순위용 점수: score 에서 단계 수만큼 감점한 값."""
        keyed = sum(step.key is not None for step in self.steps)
        return self.score - STEP_PENALTY * len(self.steps) - KEYED_STEP_PENALTY * keyed


def _expand(data: bytes) -> Iterator[Step]:
    """data 에 시도해 볼 만한 모든 (변환, 키) 조합을 적용한 결과를 만든다."""
    # 키 없는 변환을 먼저 시도한다: 같은 결과면 단순한 설명(rot13)이 caesar(13) 보다 먼저 기록되도록
    transforms = sorted(registry.all_transforms(), key=lambda t: t.needs_key)
    for t in transforms:
        if not t.looks_like(data):
            continue
        # 키가 필요한 변환은 추정한 키 후보들로, 아니면 키 없이 한 번
        keys = t.guess_keys(data) if t.needs_key else [None]
        for key in keys:
            try:
                output = t.decode(data, key)
            except TransformError:
                continue
            if output and output != data:
                yield Step(t.name, key, output)


def search(
    data: bytes,
    depth: int = DEFAULT_DEPTH,
    beam: int = DEFAULT_BEAM,
    flag_pattern: str | None = None,
) -> list[Result]:
    """data 를 최대 depth 단계까지 풀어 보고, 좋은 결과 순으로 반환한다.

    플래그를 찾으면 그 단계까지만 탐색한다 (가장 짧은 경로 우선).
    반환 순서: 플래그를 찾은 결과 → rank_score 높은 순.
    """
    pattern = compile_flag_pattern(flag_pattern)
    seen = {data}                       # 이미 만들어 본 결과는 다시 탐색하지 않는다
    frontier = [Result(steps=(), score=0.0)]
    results = []

    for _ in range(depth):
        children = []
        for node in frontier:
            current = node.data if node.steps else data
            for step in _expand(current):
                if step.output in seen:
                    continue
                seen.add(step.output)
                children.append(Result(
                    steps=node.steps + (step,),
                    score=score(step.output, pattern),
                    flag=find_flag(step.output, pattern),
                ))

        results.extend(children)
        if any(child.flag for child in children):
            break
        expandable = [c for c in children if english_score(c.data) < SOLVED_THRESHOLD]
        if not expandable:
            break
        expandable.sort(key=lambda r: r.score, reverse=True)
        frontier = expandable[:beam]

    results.sort(key=lambda r: (r.flag is None, -r.rank_score))
    return results
