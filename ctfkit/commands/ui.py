"""ctfkit ui: 그래픽 화면을 연다. 화면은 다른 명령들의 argparse 정의에서 자동으로 만들어진다."""

from ctfkit.registry import TransformError

GUI_HINTS = {"ui": {"hidden": True}}   # 화면 안에 자기 자신은 표시하지 않는다


def register(subparsers):
    p = subparsers.add_parser("ui", help="그래픽 화면(Tkinter) 실행")
    p.set_defaults(func=_run)


def _run(args):
    # CLI 만 쓸 때는 Tkinter 를 불러오지 않는다 (Linux 는 python3-tk 가 없을 수 있음)
    try:
        import tkinter
        from ctfkit.gui.app import launch
    except ImportError as e:
        raise TransformError(
            f"화면 실행에 Tkinter 가 필요합니다 ({e}). Linux 는 python3-tk 패키지를 설치하세요"
        ) from None
    try:
        return launch()
    except tkinter.TclError as e:
        raise TransformError(f"화면을 열 수 없습니다: {e}") from None
