"""web 명령 테스트.

실제 네트워크로 나가지 않도록, 로컬 임시 HTTP 서버를 띄워서 검사한다.
allowlist·curl 파싱 같은 순수 로직은 서버 없이 직접 검사한다.
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from ctfkit.cli import main
from ctfkit.commands.web import is_allowed, parse_curl


# --- 순수 로직: allowlist ---

def test_allow_localhost():
    assert is_allowed("http://localhost:8000/x")
    assert is_allowed("http://127.0.0.1/x")


def test_allow_dreamhack_suffix():
    assert is_allowed("http://host3.dreamhack.games:10000/")


def test_block_external_host():
    assert not is_allowed("http://example.com/")
    assert not is_allowed("https://evil.dreamhack.games.attacker.com/")


def test_allow_extra_host():
    assert is_allowed("http://10.0.0.5/", extra=["10.0.0.5"])
    assert is_allowed("http://foo.lab/", extra=[".lab"])


# --- 순수 로직: curl 파싱 ---

def test_parse_curl_basic():
    p = parse_curl("curl http://localhost/a")
    assert p["method"] == "GET"
    assert p["url"] == "http://localhost/a"


def test_parse_curl_headers_and_data():
    p = parse_curl("curl -X POST -H 'X-Test: 1' -d 'a=b' http://localhost/x")
    assert p["method"] == "POST"
    assert p["headers"]["X-Test"] == "1"
    assert p["data"] == "a=b"


def test_parse_curl_implicit_post():
    p = parse_curl("curl -d body http://localhost/x")
    assert p["method"] == "POST"


def test_parse_curl_no_url():
    with pytest.raises(ValueError):
        parse_curl("curl -X GET")


# --- 블록되는지: 외부 호스트는 요청 전에 거부 ---

def test_send_blocks_external(capsys):
    assert main(["web", "send", "http://example.com/"]) == 2
    assert "허용되지 않은" in capsys.readouterr().err


# --- 통합: 로컬 서버 ---

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _reply(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hello")

    do_GET = _reply
    do_POST = _reply


@pytest.fixture
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_send_local(server, capsys):
    assert main(["web", "send", f"{server}/"]) == 0
    assert "hello" in capsys.readouterr().out


def test_curl_local(server, capsys):
    assert main(["web", "curl", f"curl {server}/path"]) == 0
    assert "hello" in capsys.readouterr().out


def test_fuzz_local(server, tmp_path, capsys):
    words = tmp_path / "w.txt"
    words.write_text("a\nb\nc\n")
    assert main(["web", "fuzz", f"{server}/?id=FUZZ", "-w", str(words), "--delay", "0"]) == 0
    out = capsys.readouterr().out
    assert "HTTP 200" in out


def test_fuzz_requires_marker(tmp_path, capsys):
    words = tmp_path / "w.txt"
    words.write_text("a\n")
    assert main(["web", "fuzz", "http://localhost/no-marker", "-w", str(words)]) == 2
    assert "FUZZ" in capsys.readouterr().err


def test_fuzz_bad_hide_is_a_short_error(tmp_path, capsys):
    words = tmp_path / "words.txt"
    words.write_text("a\n")
    code = main(["web", "fuzz", "http://localhost:1/FUZZ", "--words", str(words), "--hide", "abc"])
    assert code == 2
    assert "--hide" in capsys.readouterr().err


def test_curl_option_without_value_is_a_short_error(capsys):
    assert main(["web", "curl", "curl -X"]) == 2
    assert "값이 없습니다" in capsys.readouterr().err


# --- 통합: 접두사 오라클(사물함 유형) 서버 ---

class _LockerHandler(BaseHTTPRequestHandler):
    """locker 챌린지 재현: secret[0:len(guess)] == guess 로 접두사만 비교한다."""

    SECRET = "k3z9"

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        from urllib.parse import parse_qs
        form = parse_qs(body, keep_blank_values=True)
        guess = form.get("locker_num", [""])[0]
        if guess != "" and self.SECRET[0:len(guess)] == guess:
            if guess == self.SECRET:
                result = "FLAG:DH{test_flag}"
            else:
                result = "Good"
        else:
            result = "Wrong!"
        self.send_response(200)
        self.end_headers()
        self.wfile.write(result.encode("utf-8"))


@pytest.fixture
def locker():
    srv = HTTPServer(("127.0.0.1", 0), _LockerHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_oracle_recovers_secret(locker, capsys):
    code = main(["web", "oracle", f"{locker}/", "-d", "locker_num=FUZZ",
                 "--fail", "Wrong!", "--delay", "0"])
    assert code == 0
    assert capsys.readouterr().out.strip().endswith("k3z9")


def test_oracle_needs_success_or_fail(locker, capsys):
    code = main(["web", "oracle", f"{locker}/", "-d", "locker_num=FUZZ", "--delay", "0"])
    assert code == 2
    assert "--success" in capsys.readouterr().err


def test_oracle_requires_marker(capsys):
    code = main(["web", "oracle", "http://localhost/no-marker", "--fail", "x"])
    assert code == 2
    assert "FUZZ" in capsys.readouterr().err


def test_oracle_bad_regex_is_a_short_error(locker, capsys):
    code = main(["web", "oracle", f"{locker}/", "-d", "locker_num=FUZZ",
                 "--success", "(", "--delay", "0"])
    assert code == 2
    assert "정규식" in capsys.readouterr().err


def test_oracle_blocks_external():
    assert main(["web", "oracle", "http://example.com/FUZZ", "--fail", "x"]) == 2


def test_fuzz_match_filters_by_body(locker, tmp_path, capsys):
    words = tmp_path / "w.txt"
    words.write_text("k3z8\nk3z9\nabcd\n")
    main(["web", "fuzz", f"{locker}/", "-w", str(words), "-X", "POST",
          "-d", "locker_num=FUZZ", "--match", "FLAG", "--delay", "0"])
    out = capsys.readouterr().out
    assert "k3z9" in out      # 전체 일치 -> FLAG 응답, 표시됨
    assert "abcd" not in out  # Wrong! -> 숨겨짐


# --- 통합: CBC/PKCS7 패딩 오라클 서버 (AES 라이브러리 없이 XOR 토이 블록 암호로 재현) ---
# 패딩 오라클 공격은 CBC 구조 + PKCS7 검사에만 의존하므로, D(block)=block^KEY 인
# 가역 토이 암호로도 공격 성립 여부를 그대로 검증할 수 있다.

_TOY_KEY = bytes(range(1, 9))       # 고정 키 (공격자는 모름)
_TOY_BLOCK = 8                      # 테스트 속도용 작은 블록 (알고리즘은 블록 크기 무관)
_TOY_IV = bytes(_TOY_BLOCK)         # IV = 0


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _toy_pad(data):
    p = _TOY_BLOCK - (len(data) % _TOY_BLOCK)
    return data + bytes([p]) * p


def _toy_encrypt(plain):
    data = _toy_pad(plain)
    out = b""
    prev = _TOY_IV
    for i in range(0, len(data), _TOY_BLOCK):
        blk = data[i:i + _TOY_BLOCK]
        ct = _xor(_xor(blk, prev), _TOY_KEY)   # E(x)=x^KEY, CBC
        out += ct
        prev = ct
    return out


def _toy_decrypt_valid(cipher):
    """CBC 복호 후 PKCS7 패딩이 유효한지만 돌려준다 (오라클)."""
    if len(cipher) == 0 or len(cipher) % _TOY_BLOCK != 0:
        return False
    plain = b""
    prev = _TOY_IV
    for i in range(0, len(cipher), _TOY_BLOCK):
        blk = cipher[i:i + _TOY_BLOCK]
        plain += _xor(_xor(blk, _TOY_KEY), prev)   # D(x)=x^KEY
        prev = blk
    p = plain[-1]
    return 1 <= p <= _TOY_BLOCK and plain[-p:] == bytes([p]) * p


_TOY_SECRET = b"toysec!"          # 7바이트 -> 1블록(8)로 패딩, 테스트가 빠르다


class _PaddingOracleHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(self.path).query)
        e_data = q.get("e_data", [""])[0]
        try:
            cipher = __import__("base64").b64decode(e_data)
            ok = _toy_decrypt_valid(cipher)
        except Exception:
            ok = False
        body = b'{"status":"success"}' if ok else b'{"message":"ValueError"}'
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def po_server():
    srv = HTTPServer(("127.0.0.1", 0), _PaddingOracleHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_padding_oracle_recovers_plaintext(po_server, capsys):
    import base64 as b64
    cipher_b64 = b64.b64encode(_toy_encrypt(_TOY_SECRET)).decode()
    code = main(["web", "padding-oracle", f"{po_server}/d?e_data=FUZZ",
                 "--cipher", cipher_b64, "--bad", "ValueError",
                 "--block", "8", "--iv", "00" * 8, "--delay", "0"])
    assert code == 0
    assert _TOY_SECRET.decode() in capsys.readouterr().out


def test_padding_oracle_needs_bad_or_ok(po_server, capsys):
    import base64 as b64
    cipher_b64 = b64.b64encode(_toy_encrypt(b"x")).decode()
    code = main(["web", "padding-oracle", f"{po_server}/d?e_data=FUZZ",
                 "--cipher", cipher_b64, "--delay", "0"])
    assert code == 2
    assert "--bad" in capsys.readouterr().err


def test_padding_oracle_bad_cipher_length(po_server, capsys):
    import base64 as b64
    bad = b64.b64encode(b"not-a-block").decode()
    code = main(["web", "padding-oracle", f"{po_server}/d?e_data=FUZZ",
                 "--cipher", bad, "--bad", "ValueError"])
    assert code == 2
    assert "배수" in capsys.readouterr().err


def test_padding_oracle_requires_marker(capsys):
    code = main(["web", "padding-oracle", "http://localhost/no-marker",
                 "--cipher", "AAAA", "--bad", "x"])
    assert code == 2
    assert "FUZZ" in capsys.readouterr().err
