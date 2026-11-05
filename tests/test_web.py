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
    assert main(["web", "send", "http://example.com/"]) == 1
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
    assert main(["web", "fuzz", "http://localhost/no-marker", "-w", str(words)]) == 1
    assert "FUZZ" in capsys.readouterr().err


def test_fuzz_bad_hide_is_a_short_error(tmp_path, capsys):
    words = tmp_path / "words.txt"
    words.write_text("a\n")
    code = main(["web", "fuzz", "http://localhost:1/FUZZ", "--words", str(words), "--hide", "abc"])
    assert code == 1
    assert "--hide" in capsys.readouterr().err


def test_curl_option_without_value_is_a_short_error(capsys):
    assert main(["web", "curl", "curl -X"]) == 1
    assert "값이 없습니다" in capsys.readouterr().err
