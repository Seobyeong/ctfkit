"""ctfkit hash: 해시 종류 판별 / 사전 공격 / 계산 / HMAC.

표준 라이브러리(hashlib, hmac)만 사용한다. 외부 의존성 없음.
"""

import hashlib
import hmac
import sys

from ctfkit.console import parse_key, read_input
from ctfkit.registry import TransformError

# 길이(16진수 글자 수) -> 그 길이를 갖는 흔한 해시 알고리즘 후보.
# 같은 길이를 공유하는 알고리즘이 많아서 길이만으로는 확정할 수 없다 (그래서 후보 목록).
_LENGTH_CANDIDATES = {
    32: ["md5", "md4", "ntlm"],
    40: ["sha1", "ripemd160"],
    56: ["sha224", "sha3_224"],
    64: ["sha256", "sha3_256", "blake2s"],
    96: ["sha384", "sha3_384"],
    128: ["sha512", "sha3_512", "blake2b"],
}

# hashlib 로 직접 계산할 수 있는 알고리즘 (사전 공격·계산에 사용)
_COMPUTABLE = {
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s",
}

GUI_HINTS = {
    "hash": {
        "label": "해시",
        "order": 40,
        "desc": "해시 종류 판별, 계산, 사전 공격, HMAC.",
        "actions": {"id": "판별", "sum": "계산", "crack": "사전 공격", "hmac": "HMAC"},
        "fields": {
            "digest": {"label": "해시값"},
            "words": {"label": "워드리스트"},
            # 목록은 제안일 뿐, hashlib 이 지원하는 다른 이름을 직접 입력할 수도 있다
            "algo": {"label": "알고리즘", "suggest": sorted(_COMPUTABLE), "default": "sha256"},
            "crack.algo": {"label": "알고리즘 (비우면 추정)", "default": ""},
            "data": {"label": "입력"},
            "hmac.data": {"label": "메시지"},
            "file": {"label": "또는 파일"},
            "key": {"label": "키 (0x면 16진수)"},
        },
    },
}


def _looks_hex(text: str) -> bool:
    return bool(text) and all(c in "0123456789abcdefABCDEF" for c in text)


def identify(digest: str) -> list[str]:
    """해시 문자열을 보고 가능한 알고리즘 후보를 길이·문자셋 휴리스틱으로 추린다."""
    digest = digest.strip()
    if not _looks_hex(digest):
        return []
    return _LENGTH_CANDIDATES.get(len(digest), [])


def _compute(algo: str, data: bytes) -> str:
    try:
        h = hashlib.new(algo)
    except (ValueError, TypeError) as e:
        raise TransformError(f"지원하지 않는 해시 알고리즘: {algo} ({e})") from e
    h.update(data)
    return h.hexdigest()


def register(subparsers):
    parser = subparsers.add_parser("hash", help="해시 판별·사전 공격·계산·HMAC")
    actions = parser.add_subparsers(dest="action", required=True, metavar="<action>")

    p_id = actions.add_parser("id", help="해시 종류 추정 (길이·문자셋 기준)")
    p_id.add_argument("digest", help="해시 문자열 (16진수)")
    p_id.set_defaults(func=_id)

    p_sum = actions.add_parser("sum", help="입력의 해시값 계산")
    p_sum.add_argument("algo", help="알고리즘 (md5, sha1, sha256, ...)")
    p_sum.add_argument("data", nargs="?", default="-", help="입력 (생략/'-' 면 stdin)")
    p_sum.add_argument("-f", "--file", help="파일에서 입력 읽기")
    p_sum.set_defaults(func=_sum)

    p_crack = actions.add_parser("crack", help="워드리스트로 해시의 원문을 찾는다")
    p_crack.add_argument("digest", help="찾으려는 해시값 (16진수)")
    p_crack.add_argument("-w", "--words", required=True, help="워드리스트 파일 경로 (한 줄에 하나)")
    p_crack.add_argument("-a", "--algo", help="해시 알고리즘 (생략하면 id 로 추정한 후보를 모두 시도)")
    p_crack.set_defaults(func=_crack)

    p_hmac = actions.add_parser("hmac", help="HMAC 계산")
    p_hmac.add_argument("algo", help="알고리즘 (md5, sha1, sha256, ...)")
    p_hmac.add_argument("data", nargs="?", default="-", help="메시지 (생략/'-' 면 stdin)")
    p_hmac.add_argument("-k", "--key", required=True, help="HMAC 키 ('0x' 접두사면 16진수)")
    p_hmac.add_argument("-f", "--file", help="파일에서 메시지 읽기")
    p_hmac.set_defaults(func=_hmac)


def _id(args):
    candidates = identify(args.digest)
    if not candidates:
        length = len(args.digest.strip())
        print(f"판별 실패: 알려진 길이가 아니거나 16진수가 아닙니다 (길이 {length})")
        return 1
    print(f"가능한 종류 ({len(candidates)}): {', '.join(candidates)}")
    return 0


def _sum(args):
    data = read_input(args.data, args.file)
    print(_compute(args.algo, data))
    return 0


def _crack(args):
    target = args.digest.strip().lower()
    if not _looks_hex(target):
        raise TransformError("해시값은 16진수여야 합니다")

    if args.algo:
        algos = [args.algo]
    else:
        algos = [a for a in identify(target) if a in _COMPUTABLE]
        if not algos:
            raise TransformError(
                "해시 종류를 추정할 수 없습니다. --algo 로 직접 지정하세요 (예: --algo md5)"
            )

    tried = 0
    try:
        with open(args.words, "rb") as f:
            for raw in f:
                word = raw.rstrip(b"\r\n")
                tried += 1
                for algo in algos:
                    if _compute(algo, word) == target:
                        print(f"[+] 찾음: {word.decode('utf-8', 'replace')}  ({algo}, {tried}개 시도)")
                        return 0
    except OSError as e:
        raise TransformError(f"워드리스트를 읽을 수 없습니다: {e}") from e

    print(f"[-] 찾지 못함 ({tried}개 단어, 시도 알고리즘: {', '.join(algos)})", file=sys.stderr)
    return 1


def _hmac(args):
    data = read_input(args.data, args.file)
    key = parse_key(args.key)
    try:
        mac = hmac.new(key, data, args.algo)
    except (ValueError, TypeError) as e:
        raise TransformError(f"지원하지 않는 해시 알고리즘: {args.algo} ({e})") from e
    print(mac.hexdigest())
    return 0
