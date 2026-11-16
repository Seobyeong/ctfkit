"""빔 서치(beam search)로 디코딩 경로를 탐색한다.

각 단계에서 현재 후보들에 적용 가능한 모든 변환을 시도하고,
점수가 높은 상위 beam 개만 남겨 다음 단계로 넘어간다.
"""

from collections.abc import Iterator
from dataclasses import dataclass

from ctfkit import registry
from ctfkit.analysis import english_score, printable_ratio
from ctfkit.engine.scoring import score
from ctfkit.flags import compile_flag_pattern, find_flag, flag_quality
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
# 입력에 이미 플래그가 들어 있을 때 결과에 적는 단계 이름 (변환을 하지 않았다는 표시)
PLAIN = "입력 그대로"
# 한 경로에서 글자 암호(시저·레일 펜스·뒤집기 등)를 푸는 최대 횟수.
# 글자 암호는 어떤 글자열에든 적용되므로, 여러 번 겹치면 무엇이든 만들 수 있다. 실제로 괄호가 든 평범한 문장에
# 다섯 번을 겹쳐 "dh{...}" 모양을 만들어 낸 일이 있었다. 실제 문제에서 고전 암호를 세 겹 이상 쌓는 경우는 드물다.
MAX_TEXT_CIPHERS = 2


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


def _worth_trying(t, previous, data: bytes, ciphers_used: int = 0) -> bool:
    """직전 단계(previous) 다음에 변환 t 를 시도할 가치가 있는가.

    변환이 늘면 조합도 늘고, 조합이 늘면 우연히 플래그 모양이 된 쓰레기(오탐)도 늘어난다.
    의미 없는 조합을 미리 잘라 낸다.
    """
    if t.text_cipher and ciphers_used >= MAX_TEXT_CIPHERS:
        return False
    if previous is None:
        # 0) 사람이 붙여 넣은 글자 입력에 곧바로 XOR 을 시도하지 않는다. XOR 암호문은 hex·base64 로 적혀서 오거나
        #    파일(출력할 수 없는 바이트가 섞인 데이터)로 온다. 글자 입력에 플래그 접두사를 가정한 키를 대면
        #    "&#54;&#56;..." 같은 규칙적인 글자열에서 가짜 플래그가 나온다.
        return t.name != "xor" or printable_ratio(data) < 1.0
    # 1) 키가 필요한 같은 암호를 연달아 두 번: 시저 두 번은 시저 한 번과 같고, 레일 펜스를 두 번 푸는 것은
    #    글자를 아무렇게나 섞는 것과 같다.
    if t.needs_key and t.name == previous.name:
        return False
    # 2) 글자 암호를 푼 결과에 XOR: XOR 암호문은 hex·base64 를 풀어 나온 바이트로 주어진다. 글자를 섞거나 민
    #    결과에 XOR 을 시도하면, 플래그 접두사에 맞춘 키가 그럴듯한 가짜 플래그를 만든다.
    if t.name == "xor" and previous.text_cipher:
        return False
    return True


def _expand(data: bytes, previous=None, ciphers_used: int = 0) -> Iterator[Step]:
    """data 에 시도해 볼 만한 모든 (변환, 키) 조합을 적용한 결과를 만든다. previous 는 직전 단계의 변환."""
    # 키 없는 변환을 먼저 시도한다: 같은 결과면 단순한 설명(rot13)이 caesar(13) 보다 먼저 기록되도록
    transforms = sorted(registry.all_transforms(), key=lambda t: t.needs_key)
    for t in transforms:
        if not _worth_trying(t, previous, data, ciphers_used) or not t.looks_like(data):
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
    반환 순서: 플래그를 찾은 결과(플래그다운 순) → rank_score 높은 순.
    """
    pattern = compile_flag_pattern(flag_pattern)
    if find_flag(data, pattern):
        # 입력에 이미 플래그가 있다. 변환을 시도하면 멀쩡한 플래그를 망가뜨린 후보만 나온다
        return [Result(steps=(Step(PLAIN, None, data),), score=1.0, flag=find_flag(data, pattern))]
    seen = {data}                       # 이미 만들어 본 결과는 다시 탐색하지 않는다
    frontier = [Result(steps=(), score=0.0)]
    results = []

    for _ in range(depth):
        children = []
        for node in frontier:
            current = node.data if node.steps else data
            previous = registry.get(node.steps[-1].transform) if node.steps else None
            ciphers_used = sum(registry.get(s.transform).text_cipher for s in node.steps)
            for step in _expand(current, previous, ciphers_used):
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

    # 플래그를 찾은 결과가 여럿이면 플래그다운 쪽(영숫자·밑줄 위주)을 앞에 둔다
    results.sort(key=lambda r: (r.flag is None, -flag_quality(r.flag), -r.rank_score))
    return results
