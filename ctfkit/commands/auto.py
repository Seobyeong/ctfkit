"""ctfkit auto: 여러 겹으로 인코딩·암호화된 데이터를 자동으로 푼다."""

from ctfkit.console import preview, read_input
from ctfkit.engine import search
from ctfkit.engine.search import DEFAULT_BEAM, DEFAULT_DEPTH
from ctfkit.registry import TransformError


def register(subparsers):
    p = subparsers.add_parser("auto", help="디코딩 경로를 자동으로 탐색")
    p.add_argument("data", nargs="?", default="-", help="입력 문자열 (생략하거나 '-' 면 stdin)")
    p.add_argument("-f", "--file", help="파일에서 입력 읽기")
    p.add_argument("-d", "--depth", type=int, default=DEFAULT_DEPTH,
                   help=f"최대 단계 수 (기본 {DEFAULT_DEPTH})")
    p.add_argument("-b", "--beam", type=int, default=DEFAULT_BEAM,
                   help=f"단계마다 남길 후보 수 (기본 {DEFAULT_BEAM})")
    p.add_argument("--flag", metavar="REGEX",
                   help=r"플래그 정규식 (기본: DH{...}, flag{...} 등. 예: 'myctf\{.*?\}')")
    p.add_argument("-n", "--top", type=int, default=3, help="플래그가 없을 때 보여줄 후보 수 (기본 3)")
    p.set_defaults(func=_run)


def _step_label(step) -> str:
    return f"{step.transform}({step.key})" if step.key else step.transform


def _print_path(result) -> None:
    for i, step in enumerate(result.steps, 1):
        print(f"  [{i}] {_step_label(step):<22} -> {preview(step.output)}")


def _run(args):
    if args.depth < 1 or args.beam < 1:
        raise TransformError("--depth 와 --beam 은 1 이상이어야 합니다")
    data = read_input(args.data, args.file)
    try:
        results = search(data, depth=args.depth, beam=args.beam, flag_pattern=args.flag)
    except ValueError as e:   # 잘못된 --flag 정규식
        raise TransformError(str(e)) from e

    if results and results[0].flag:
        best = results[0]
        print(f"[+] 플래그 발견 ({len(best.steps)}단계)")
        _print_path(best)
        print(best.flag.decode("ascii", errors="replace"))
        return 0

    if not results:
        print("[-] 적용할 수 있는 변환이 없습니다.")
        return 1

    print(f"[-] 플래그를 찾지 못했습니다. 점수가 높은 후보 {min(args.top, len(results))}개:")
    for rank, result in enumerate(results[:args.top], 1):
        print(f"\n#{rank}  score={result.rank_score:.2f}")
        _print_path(result)
    return 1
