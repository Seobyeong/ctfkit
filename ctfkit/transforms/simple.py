"""키 없이 한 번에 되돌리는 간단한 치환·전치: 뒤집기, ROT47, 아트배시.

셋 다 인코딩과 디코딩이 같은 연산이다. 거의 모든 입력에 적용할 수 있어서, auto 가 아무 데나 시도하면
탐색 후보가 불어난다. 그래서 looks_like 를 좁게 잡는다.
"""

from ctfkit.analysis import english_score, letter_ratio, looks_encoded, printable_ratio
from ctfkit.flags import compile_flag_pattern
from ctfkit.registry import Transform, TransformError, register

_ATBASH = bytes.maketrans(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    b"zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA",
)
_ROT47 = bytes(33 + (b - 33 + 47) % 94 if 33 <= b <= 126 else b for b in range(256))
_FLAG_RE = compile_flag_pattern()
_REVERSE_PROBE_LIMIT = 4096   # 이보다 긴 입력은 "뒤집으면 다른 변환이 풀리는가" 검사를 하지 않는다


@register
class Reverse(Transform):
    name = "reverse"
    text_cipher = True
    aliases = ("rev",)
    description = "뒤집기 (맨 뒤 글자가 맨 앞으로)"

    def decode(self, data, key=None):
        return data[::-1]

    def encode(self, data, key=None):
        return data[::-1]

    def looks_like(self, data):
        s = data.strip()
        if len(s) < 4:
            return False
        # 1) 뒤집힌 플래그: 닫는 괄호가 여는 괄호보다 앞에 있다.  2) 뒤집힌 base64: 패딩이 맨 앞에 있다.
        if s.startswith(b"=") or (b"}" in s and b"{" in s and s.index(b"}") < s.index(b"{")):
            return True
        # 3) 그대로는 글자가 안 나오는데 뒤집으면 다른 변환이 글자를 내는 경우 (예: 뒤집힌 hex)
        return len(s) <= _REVERSE_PROBE_LIMIT and _unlocks(s)


def _decodes_to_text(data: bytes) -> bool:
    from ctfkit import registry

    for t in registry.all_transforms():
        # 글자 암호(rot13, atbash 등)는 어떤 입력에도 글자를 내놓아 판별에 쓸 수 없으므로 뺀다
        if t.needs_key or t.lossy or t.text_cipher or not t.looks_like(data):
            continue
        try:
            out = t.decode(data)
        except TransformError:
            continue
        if len(out) >= 4 and out != data and printable_ratio(out) >= 0.95:
            return True
    return False


def _unlocks(data: bytes) -> bool:
    return not _decodes_to_text(data) and _decodes_to_text(data[::-1])


@register
class Rot47(Transform):
    name = "rot47"
    text_cipher = True
    description = "ROT47 (출력 가능한 ASCII 94자를 47칸 회전, 인코딩과 디코딩이 같음)"

    def decode(self, data, key=None):
        return data.translate(_ROT47)

    def encode(self, data, key=None):
        return data.translate(_ROT47)

    def looks_like(self, data):
        s = data.strip()
        if len(s) < 4 or any(not (32 <= b <= 126) for b in s):
            return False
        # ROT47 은 글자를 기호·숫자·대문자로 흩어 놓아서 겉모양만으로는 알아보기 어렵다.
        # 계산이 싸므로 한 번 풀어 보고, 플래그가 나오거나 훨씬 영어다워질 때만 후보로 삼는다
        plain = s.translate(_ROT47)
        return bool(_FLAG_RE.search(plain)) or english_score(plain) >= english_score(s) + 0.3


@register
class Atbash(Transform):
    name = "atbash"
    text_cipher = True
    description = "아트배시 (알파벳 뒤집기 a↔z, 인코딩과 디코딩이 같음)"

    def decode(self, data, key=None):
        return data.translate(_ATBASH)

    def encode(self, data, key=None):
        return data.translate(_ATBASH)

    def looks_like(self, data):
        return letter_ratio(data) >= 0.5 and not looks_encoded(data)
