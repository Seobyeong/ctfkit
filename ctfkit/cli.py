"""ctfkit 명령줄 진입점. commands/ 안의 모듈을 자동으로 서브커맨드로 붙인다.

시작 시간을 줄이려고 **실행할 명령의 모듈만** 불러온다(지연 로딩). `ctfkit hash ...` 를 실행하는데
web 모듈의 urllib 까지 불러올 필요는 없기 때문이다. 어떤 명령인지 알 수 없을 때(`ctfkit -h`,
잘못된 명령 이름 등)는 예전처럼 모든 모듈을 불러온다. 두 경로의 동작은 같고 속도만 다르다.
"""

import argparse
import importlib
import importlib.util
import os
import sys

from ctfkit import __version__, commands, console
from ctfkit.registry import TransformError, module_names

# 종료 코드. 에이전트와 스크립트가 출력을 읽지 않고도 결과를 구분할 수 있게 세 가지로 나눈다.
EXIT_OK = 0          # 답을 찾았다 / 정상적으로 끝났다
EXIT_NOT_FOUND = 1   # 실행은 됐지만 찾는 것이 없다 (플래그 없음, 사전에 없음 등). 명령이 직접 반환한다
EXIT_ERROR = 2       # 입력·파일·사용법 오류. argparse 의 사용법 오류도 2 다


def _terminal_width() -> int:
    """도움말 줄 폭. shutil.get_terminal_size() 와 같은 규칙(COLUMNS → 터미널 → 80)이다."""
    try:
        columns = int(os.environ["COLUMNS"])
    except (KeyError, ValueError):
        columns = 0
    if columns <= 0:
        try:
            columns = os.get_terminal_size(sys.__stdout__.fileno()).columns
        except (AttributeError, ValueError, OSError):
            columns = 80
    return columns - 2


class _Formatter(argparse.HelpFormatter):
    """폭을 미리 정해 주는 도움말 포매터.

    argparse 는 폭이 없으면 shutil 을 불러와 터미널 크기를 잰다. 그런데 add_argument 를 부를 때마다
    포매터를 만들기 때문에, 도움말을 출력하지 않는 실행에서도 shutil(+bz2, lzma)을 불러오게 된다.
    """

    def __init__(self, prog, **kwargs):
        if kwargs.get("width") is None:
            kwargs["width"] = _terminal_width()
        super().__init__(prog, **kwargs)


class _Parser(argparse.ArgumentParser):
    """기본 포매터가 _Formatter 인 파서. add_subparsers 가 같은 클래스로 하위 파서를 만들므로
    명령 모듈이 만드는 파서에도 그대로 적용된다."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("formatter_class", _Formatter)
        super().__init__(*args, **kwargs)


def _new_parser():
    parser = _Parser(prog="ctfkit", description="CTF 워게임 보조 도구",
                     epilog="어떤 명령을 쓸지 모르겠으면: ctfkit guide   (종료 코드: 0 찾음 / 1 못 찾음 / 2 오류)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="진행·안내(stderr) 를 끄고 결과(stdout)만 출력 (AI·파이프 전달용)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="<command>")
    return parser, subparsers


def _register(module_name: str, subparsers) -> None:
    importlib.import_module(f"{commands.__name__}.{module_name}").register(subparsers)


def build_parser() -> argparse.ArgumentParser:
    """모든 명령을 붙인 파서. 도움말, 그래픽 화면(gui/schema.py), 테스트가 쓴다."""
    parser, subparsers = _new_parser()
    for name in module_names(commands):
        _register(name, subparsers)
    return parser


def _requested_command(argv: list[str]) -> str | None:
    """인자에서 서브커맨드 이름을 찾는다. 전역 옵션(-q 등)은 값을 받지 않으므로 건너뛰면 된다."""
    for arg in argv:
        if not arg.startswith("-"):
            return arg
    return None


def _module_for(command: str) -> str | None:
    """명령 이름에 해당하는 commands/ 모듈 이름. 없으면 None."""
    name = commands.ALIASES.get(command, command)
    if not name.isidentifier() or name.startswith("_"):
        return None
    if importlib.util.find_spec(f"{commands.__name__}.{name}") is None:
        return None
    return name


def _parser_for(argv: list[str]) -> argparse.ArgumentParser:
    """argv 를 처리할 파서. 가능하면 명령 하나만 붙인 가벼운 파서를 만든다."""
    command = _requested_command(argv)
    module = _module_for(command) if command else None
    if module:
        parser, subparsers = _new_parser()
        _register(module, subparsers)
        if command in subparsers.choices:
            return parser
    # 명령을 알 수 없거나, 모듈이 그 이름의 명령을 등록하지 않았다 → 전체를 불러온다
    return build_parser()


def _avoid_encoding_crash() -> None:
    # 출력 인코딩이 한글을 표현하지 못해도(예: 영어 Windows 의 cp1252 로 파이프 출력) 죽지 않고
    # 표현할 수 없는 문자만 '?' 로 바꿔 출력한다
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")


def main(argv: list[str] | None = None) -> int:
    _avoid_encoding_crash()
    if argv is None:
        argv = sys.argv[1:]
    args = _parser_for(argv).parse_args(argv)
    console.QUIET = getattr(args, "quiet", False)
    try:
        return args.func(args)
    except TransformError as e:
        print(f"오류: {e}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as e:
        # --file 경로가 없거나 읽을 수 없을 때
        print(f"오류: {e}", file=sys.stderr)
        return EXIT_ERROR
