"""변환(Transform) 플러그인 레지스트리.

새 변환을 추가하려면 ctfkit/transforms/ 에 파일을 만들고
Transform 을 상속한 클래스에 @register 를 붙이면 된다.
CLI, 테스트, (v0.2의) auto 엔진은 모두 이 레지스트리만 보고 동작한다.
"""

import importlib
import pkgutil


class TransformError(Exception):
    """변환 실패 (잘못된 입력, 키 누락 등). CLI는 이 오류를 짧은 메시지로 출력한다."""


class Transform:
    """모든 변환의 기본 클래스. 입력과 출력은 항상 bytes 다."""

    name = ""            # 명령어에서 쓰는 이름 (예: "base64")
    aliases = ()         # 별칭 (예: ("b64",))
    description = ""     # `ctfkit codec list` 에 표시되는 설명
    needs_key = False    # XOR·시저처럼 키가 필요한 변환이면 True
    example_key = None   # needs_key 일 때 테스트·도움말에 쓰는 예시 키

    def decode(self, data: bytes, key: str | None = None) -> bytes:
        raise NotImplementedError

    def encode(self, data: bytes, key: str | None = None) -> bytes:
        raise NotImplementedError

    def looks_like(self, data: bytes) -> bool:
        # auto 엔진이 시도할 가치가 있는지 빠르게 거르는 용도. 기본은 항상 시도.
        return True


_transforms = []   # 등록 순서대로 보관
_lookup = {}       # 이름·별칭 -> 인스턴스
_discovered = False


def register(cls):
    """클래스 데코레이터: 변환을 레지스트리에 등록한다."""
    t = cls()
    if not t.name:
        raise ValueError(f"{cls.__name__}: name 이 비어 있습니다")

    names = [n.lower() for n in (t.name, *t.aliases)]
    # 하나라도 겹치면 아무것도 등록하지 않는다
    for n in names:
        if n in _lookup:
            raise ValueError(f"이미 등록된 변환 이름입니다: {n}")
    for n in names:
        _lookup[n] = t
    _transforms.append(t)
    return cls


def discover():
    """ctfkit/transforms/ 안의 모든 모듈을 import 해서 @register 가 실행되게 한다."""
    global _discovered
    if _discovered:
        return
    from ctfkit import transforms

    for module in pkgutil.iter_modules(transforms.__path__):
        importlib.import_module(f"{transforms.__name__}.{module.name}")
    _discovered = True


def get(name: str) -> Transform:
    """이름이나 별칭으로 변환을 찾는다."""
    discover()
    try:
        return _lookup[name.lower()]
    except KeyError:
        available = ", ".join(t.name for t in _transforms)
        raise TransformError(f"알 수 없는 변환: {name} (사용 가능: {available})") from None


def all_transforms() -> list[Transform]:
    """등록된 모든 변환을 등록 순서대로 반환한다."""
    discover()
    return list(_transforms)
