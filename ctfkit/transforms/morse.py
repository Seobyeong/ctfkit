"""모스 부호. 대소문자와 일부 기호(예: 중괄호)를 표현할 수 없어 왕복이 보장되지 않는다(lossy)."""

import re

from ctfkit.registry import Transform, TransformError, register

_TABLE = {
    "a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".", "f": "..-.", "g": "--.", "h": "....", "i": "..",
    "j": ".---", "k": "-.-", "l": ".-..", "m": "--", "n": "-.", "o": "---", "p": ".--.", "q": "--.-", "r": ".-.",
    "s": "...", "t": "-", "u": "..-", "v": "...-", "w": ".--", "x": "-..-", "y": "-.--", "z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....",
    "7": "--...", "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.", "!": "-.-.--", "/": "-..-.", "(": "-.--.",
    ")": "-.--.-", "&": ".-...", ":": "---...", ";": "-.-.-.", "=": "-...-", "+": ".-.-.", "-": "-....-",
    "_": "..--.-", '"': ".-..-.", "$": "...-..-", "@": ".--.-.",
}
_REVERSE = {code: char for char, code in _TABLE.items()}
_MORSE_RE = re.compile(rb"^[.\-_/|\s]+$")


@register
class Morse(Transform):
    name = "morse"
    description = "모스 부호 (글자는 공백, 단어는 / 로 구분). 대소문자는 복원되지 않음"
    lossy = True

    def decode(self, data, key=None):
        try:
            text = data.decode("ascii").strip()
        except UnicodeDecodeError as e:
            raise TransformError(f"모스 부호가 아닙니다: {e}") from e
        text = text.replace("_", "-")
        out = []
        for word in re.split(r"\s*[/|]\s*|\s{3,}", text):
            for code in word.split():
                if code not in _REVERSE:
                    raise TransformError(f"알 수 없는 모스 부호: {code[:12]}")
                out.append(_REVERSE[code])
            out.append(" ")
        return "".join(out).strip().encode("ascii")

    def encode(self, data, key=None):
        words = data.decode("utf-8", "replace").lower().split()
        return " / ".join(" ".join(_TABLE[c] for c in word if c in _TABLE) for word in words).encode("ascii")

    def looks_like(self, data):
        return bool(_MORSE_RE.match(data)) and len(data.split()) >= 3 and (b"." in data or b"-" in data)
