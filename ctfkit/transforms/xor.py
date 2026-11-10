from itertools import cycle

from ctfkit.analysis import english_score, looks_encoded, text_score
from ctfkit.flags import FLAG_PREFIXES
from ctfkit.registry import Transform, TransformError, register

# 키 추정 때 앞부분만 보고 점수를 매긴다 (긴 데이터에서 256번 반복하는 비용 절약)
GUESS_SAMPLE_SIZE = 2048
# english_score 가 이보다 높으면 이미 평문으로 보고 XOR 을 시도하지 않는다
ENGLISH_THRESHOLD = 0.5
# 다중 바이트 키 길이 추정을 시도하는 최소 데이터 길이.
# 너무 짧으면 해밍 거리 통계가 흔들려 엉뚱한 키 길이를 고른다.
MULTIBYTE_MIN = 40
# 추정할 반복 키의 최대 길이
MAX_KEY_LENGTH = 40
# 해밍 거리로 고른 키 길이 후보 중 상위 몇 개를 쓸지 (약수까지 넓혀서 실제로 풀어 본다)
LENGTH_CANDIDATES = 5
# 키 1바이트당 점수에서 깎는 양. 긴 키는 자리마다 따로 최적화돼 점수가 부풀려지므로
# (과적합), 같은 평문을 주는 짧은 키가 이기도록 길이에 비례해 감점한다.
LENGTH_PENALTY = 0.003


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


def _hamming(a: bytes, b: bytes) -> int:
    """두 바이트열의 비트 단위 해밍 거리 (다른 비트 수)."""
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def _divisors(n: int) -> set[int]:
    """2 이상 n 이하인 n 의 약수들."""
    return {d for d in range(2, n + 1) if n % d == 0}


def _key_length_candidates(data: bytes, limit: int) -> list[int]:
    """반복 키 XOR 의 키 길이 후보를 해밍 거리로 추린다.

    키 길이가 L 이면, L 바이트씩 끊은 블록들은 같은 키로 XOR 되어
    (평문 ^ 평문) 만 남으므로 서로 비트가 적게 다르다. 즉 길이로 정규화한
    해밍 거리가 진짜 키 길이(와 그 배수)에서 작아진다 (Friedman/Kasiski 아이디어).

    짧은 데이터에선 해밍만으로 정확한 길이를 집기 어렵지만 "진짜 주기의 배수"가
    상위에 몰리므로, 상위 길이와 그 **약수**를 함께 후보로 돌려준다. 실제 어느
    길이가 맞는지는 호출한 쪽에서 복호문 점수로 가린다.
    """
    max_len = min(MAX_KEY_LENGTH, len(data) // 4)
    scored = []
    for length in range(2, max_len + 1):
        blocks = [data[i * length:(i + 1) * length] for i in range(len(data) // length)]
        pairs = list(zip(blocks, blocks[1:]))
        if not pairs:
            continue
        avg = sum(_hamming(a, b) for a, b in pairs) / (len(pairs) * length)
        scored.append((avg, length))
    scored.sort()

    candidates = set()
    for _, length in scored[:limit]:
        candidates.add(length)
        candidates |= _divisors(length)
    return sorted(candidates)


def _break_repeating_key(data: bytes, length: int) -> bytes:
    """키 길이를 안다고 보고, 각 자리를 1바이트 XOR 로 따로 풀어 키를 맞춘다."""
    key = bytearray()
    for i in range(length):
        column = data[i::length]
        best = max(range(256), key=lambda k: text_score(_xor(column, bytes([k]))))
        key.append(best)
    return bytes(key)


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
        """빠른 키 추정 (auto 탐색이 노드마다 부른다): 알려진 평문 + 1바이트 키."""
        if not data:
            return []
        # 1) 플래그 접두사를 이용한 알려진 평문 공격 (여러 바이트 키도 찾을 수 있다).
        #    접두사로 검증된 고신뢰 키라 항상 맨 앞에 둔다.
        keys = _known_plaintext_keys(data)
        # 2) 1바이트 키 256개를 텍스트다움 순으로 정렬 (통계적 추정)
        sample = data[:GUESS_SAMPLE_SIZE]
        ranked = sorted(range(256), key=lambda k: text_score(_xor(sample, bytes([k]))), reverse=True)
        single = [bytes([k]) for k in ranked if bytes([k]) not in keys][:limit]
        return ["0x" + key.hex() for key in keys + single]

    def crack_keys(self, data, limit=3):
        """철저한 키 추정 (crack 명령 전용): 위 결과에 **다중 바이트 반복 키**를 더한다.

        해밍 거리로 키 길이를 추정하고(_key_length_candidates) 각 자리를 1바이트
        XOR 로 풀어(_break_repeating_key) 알려진 평문 없이도 반복 키를 복구한다.
        길이 추정·열별 풀이가 무거워 auto 핫패스(guess_keys)에는 넣지 않는다.
        """
        if not data:
            return []
        keys = _known_plaintext_keys(data)
        sample = data[:GUESS_SAMPLE_SIZE]

        candidates = [bytes([k]) for k in range(256)]
        if len(data) >= MULTIBYTE_MIN:
            for length in _key_length_candidates(sample, LENGTH_CANDIDATES):
                candidates.append(_break_repeating_key(sample, length))

        # 텍스트다움에서 길이 패널티를 뺀 값으로 정렬한다. 긴 키일수록 자리마다 따로
        # 최적화돼 점수가 부풀려지므로(과적합), 같은 평문을 주는 짧은 키가 이기도록 한다.
        def rank(k: bytes) -> tuple[float, int]:
            return (-(text_score(_xor(sample, k)) - LENGTH_PENALTY * len(k)), len(k))

        seen = set(keys)
        ranked = []
        for key in sorted(candidates, key=rank):
            if key not in seen:
                seen.add(key)
                ranked.append(key)

        return ["0x" + key.hex() for key in keys + ranked[:limit]]
