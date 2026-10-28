"""ctfkit 명령줄 진입점. commands/ 안의 모듈을 자동으로 서브커맨드로 붙인다."""

import argparse
import importlib
import pkgutil
import sys

from ctfkit import __version__, commands
from ctfkit.registry import TransformError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ctfkit", description="CTF 워게임 보조 도구")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    for module in pkgutil.iter_modules(commands.__path__):
        importlib.import_module(f"{commands.__name__}.{module.name}").register(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except TransformError as e:
        print(f"오류: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        # --file 경로가 없거나 읽을 수 없을 때
        print(f"오류: {e}", file=sys.stderr)
        return 1
