"""ctfkit crypto: 블록 암호 CTF에서 자주 쓰는, 키 없이도 되는 바이트 조작 도구.

표준 라이브러리만 사용한다 (AES 자체 암복호화처럼 암호 라이브러리가 필요한 기능은 넣지 않는다).
  - cbc-flip   : CBC 비트플립. 이전 블록(또는 IV) 바이트를 바꿔 다음 블록 평문을 원하는 값으로.
  - pkcs7-pad  : PKCS7 패딩을 붙인다.
  - pkcs7-unpad: PKCS7 패딩을 떼어낸다.
"""

import base64
import binascii
import sys

from ctfkit.registry import TransformError

GUI_HINTS = {
    "crypto": {
        "label": "크립토 조작",
        "order": 35,
        "desc": "키 없이 하는 블록 암호 바이트 조작 (CBC 비트플립·PKCS7).",
        "actions": {"cbc-flip": "CBC 비트플립", "pkcs7-pad": "PKCS7 패딩", "pkcs7-unpad": "PKCS7 제거"},
        "fields": {
            "cipher": {"label": "암호문(base64)"},
            "iv": {"label": "IV(hex)"},
            "offset": {"label": "평문 오프셋"},
            "known": {"label": "현재 평문"},
            "desired": {"label": "바꿀 평문"},
            "data": {"label": "입력(hex)"},
            "block": {"label": "블록 크기"},
        },
    },
}


def register(subparsers):
    p = subparsers.add_parser("crypto", help="블록 암호 바이트 조작 (cbc-flip, pkcs7)")
    actions = p.add_subparsers(dest="action", required=True, metavar="<action>")

    p_flip = actions.add_parser("cbc-flip", help="CBC 비트플립: 이전 블록을 조작해 평문 바꾸기")
    p_flip.add_argument("--cipher", required=True, metavar="B64", help="원본 암호문 (base64)")
    p_flip.add_argument("--offset", type=int, required=True, help="바꿀 평문의 시작 위치(바이트)")
    p_flip.add_argument("--known", required=True, help="그 위치의 현재 평문")
    p_flip.add_argument("--desired", required=True, help="그 위치에 넣고 싶은 평문 (현재 평문과 같은 길이)")
    p_flip.add_argument("--iv", metavar="HEX", help="IV (hex). 첫 블록(offset<블록)을 바꿀 때 필요")
    p_flip.add_argument("--block", type=int, default=16, help="블록 크기 바이트 (기본 16)")
    p_flip.set_defaults(func=_cbc_flip)

    p_pad = actions.add_parser("pkcs7-pad", help="PKCS7 패딩 붙이기 (입력 hex -> 출력 hex)")
    p_pad.add_argument("data", help="입력 데이터 (hex)")
    p_pad.add_argument("--block", type=int, default=16, help="블록 크기 바이트 (기본 16)")
    p_pad.set_defaults(func=_pkcs7_pad)

    p_unpad = actions.add_parser("pkcs7-unpad", help="PKCS7 패딩 떼기 (입력 hex -> 출력 hex)")
    p_unpad.add_argument("data", help="입력 데이터 (hex)")
    p_unpad.add_argument("--block", type=int, default=16, help="블록 크기 바이트 (기본 16)")
    p_unpad.set_defaults(func=_pkcs7_unpad)


def _b64_to_bytes(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as e:
        raise TransformError(f"{label} 가 올바른 base64 가 아닙니다: {e}") from e


def _hex_to_bytes(value: str, label: str) -> bytes:
    try:
        return bytes.fromhex(value.replace(" ", ""))
    except ValueError as e:
        raise TransformError(f"{label} 가 올바른 hex 가 아닙니다: {e}") from e


def _cbc_flip(args):
    if args.block < 2:
        raise TransformError("--block 은 2 이상이어야 합니다")
    block = args.block
    cipher = bytearray(_b64_to_bytes(args.cipher, "--cipher"))
    if len(cipher) % block != 0:
        raise TransformError(f"암호문 길이({len(cipher)})가 블록 크기({block})의 배수가 아닙니다")

    known = args.known.encode("latin-1")
    desired = args.desired.encode("latin-1")
    if len(known) != len(desired):
        raise TransformError("--known 과 --desired 의 길이가 같아야 합니다")
    if args.offset < 0:
        raise TransformError("--offset 은 0 이상이어야 합니다")
    if args.offset + len(known) > len(cipher):
        raise TransformError("바꿀 범위가 암호문 길이를 벗어납니다")

    iv = None
    if args.iv is not None:
        iv = bytearray(_hex_to_bytes(args.iv, "--iv"))
        if len(iv) != block:
            raise TransformError(f"--iv 길이는 블록 크기({block})와 같아야 합니다")

    iv_touched = False
    for k in range(len(known)):
        pos = args.offset + k
        b, i = pos // block, pos % block
        delta = known[k] ^ desired[k]
        if b == 0:
            if iv is None:
                raise TransformError(
                    "offset 이 첫 블록이라 IV 를 조작해야 합니다. --iv 로 IV(hex)를 주세요."
                )
            iv[i] ^= delta
            iv_touched = True
        else:
            cipher[(b - 1) * block + i] ^= delta

    print(f"cipher(b64): {base64.b64encode(bytes(cipher)).decode('ascii')}")
    print(f"cipher(hex): {bytes(cipher).hex()}")
    if iv_touched:
        print(f"iv(hex):     {bytes(iv).hex()}")
        print("[!] 첫 블록을 바꿨습니다. 조작한 IV 로 요청하세요.", file=sys.stderr)
    return 0


def _pkcs7_pad(args):
    if args.block < 2 or args.block > 255:
        raise TransformError("--block 은 2 이상 255 이하여야 합니다")
    data = _hex_to_bytes(args.data, "data")
    p = args.block - (len(data) % args.block)
    print((data + bytes([p]) * p).hex())
    return 0


def _pkcs7_unpad(args):
    if args.block < 2 or args.block > 255:
        raise TransformError("--block 은 2 이상 255 이하여야 합니다")
    data = _hex_to_bytes(args.data, "data")
    if not data or len(data) % args.block != 0:
        raise TransformError(f"데이터 길이({len(data)})가 블록 크기({args.block})의 배수가 아닙니다")
    p = data[-1]
    if p < 1 or p > args.block or data[-p:] != bytes([p]) * p:
        raise TransformError("PKCS7 패딩이 유효하지 않습니다")
    print(data[:-p].hex())
    return 0
