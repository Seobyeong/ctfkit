from itertools import cycle

from ctfkit.analysis import english_score, looks_encoded, text_score
from ctfkit.flags import FLAG_PREFIXES
from ctfkit.registry import Transform, TransformError, register

# 키 추정 때 앞부분만 보고 점수를 매긴다 (긴 데이터에서 256번 반복하는 비용 절약)
GUESS_SAMPLE_SIZE = 2048
# english_score 가 이보다 높으면 이미 평문으로 보고 XOR 을 시도하지 않는다
ENGLISH_THRESHOLD = 0.5


def parse_key(key: str | None) -> bytes:
    """키 문자열을 bytes 로 바꾼다. '0x' 로 시작하면 16진수, 아니면 문자열 그대로."""
    if not key:
        raise TransformError("XOR 키가 비어 있습니다")
    if key[:2].lower() == "0x":
        try:
            return bytes.fromhex(key[2:])
        except ValueError as e:
            raise TransformError(f"잘못된 16진수 키: {key} ({e})") from e
    return key.encode("utf-8")


def _xor(data: bytes, key: bytes) -> bytes:
    # 키가 데이터보다 짧으면 반복해서 사용한다
    return bytes(b ^ k for b, k in zip(data, cycle(key)))


def _known_plaintext_keys(data: bytes) -> list[bytes]:
    """알려진 평문 공격: 데이터가 플래그 접두사(예: "DH{")로 시작한다고 가정하고 키를 계산한다.

    암호문 ^ 평문 = 키 이므로, 앞 L 바이트로 길이 L 키를 구하고
    접두사의 나머지 바이트로 그 키가 맞는지 검증한다 (L < 접두사 길이일 때만 검증 가능).
    """
    keys = []
    for prefix in FLAG_PREFIXES:
        known = (prefix + "{").encode()
        if len(data) < len(known):
            continue
        for length in range(1, len(known)):
            key = _xor(data[:length], known[:length])
            if _xor(data[:len(known)], key) == known and key not in keys:
                keys.append(key)
                break   # 가장 짧은 키만
    return keys


@register
class Xor(Transform):
    name = "xor"
    description = "반복 키 XOR (키: 0x20, 0x4142 처럼 16진수 또는 일반 문자열)"
    needs_key = True
    example_key = "0x20"

    def decode(self, data, key=None):
        return _xor(data, parse_key(key))

    def encode(self, data, key=None):
        # XOR 은 같은 키로 한 번 더 하면 원래대로 돌아온다
        return self.decode(data, key)

    def looks_like(self, data):
        # 이미 영어처럼 읽히는 텍스트나 base64 같은 인코딩 문자열에는 시도하지 않는다.
        # (출력 가능 여부만 보면 안 된다: 영어 문장을 0x5a 로 XOR 해도 대부분 출력 가능 문자다)
        return bool(data) and not looks_encoded(data) and english_score(data) < ENGLISH_THRESHOLD

    def guess_keys(self, data, limit=3):
        if not data:
            return []
        # 1) 플래그 접두사를 이용한 알려진 평문 공격 (여러 바이트 키도 찾을 수 있다)
        keys = _known_plaintext_keys(data)

        # 2) 1바이트 키 256개를 모두 시도해 텍스트처럼 보이는 순서로 정렬 (통계적 추정)
        #    알려진 평문 키와 별개로 limit 개를 더한다
        sample = data[:GUESS_SAMPLE_SIZE]
        ranked = sorted(range(256), key=lambda k: text_score(_xor(sample, bytes([k]))), reverse=True)
        statistical = [bytes([k]) for k in ranked if bytes([k]) not in keys][:limit]

        return ["0x" + key.hex() for key in keys + statistical]
