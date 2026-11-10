"""jwt 명령 테스트 (decode, forge, crack). 표준 라이브러리만으로 검증한다."""

import base64
import hashlib
import hmac
import json

from ctfkit.cli import main


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _make_token(header: dict, payload: dict, secret: bytes | None = None) -> str:
    hb = _b64url(json.dumps(header, separators=(",", ":")).encode())
    pb = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{hb}.{pb}".encode("ascii")
    if secret is None:
        sig = ""
    else:
        sig = _b64url(hmac.new(secret, signing_input, hashlib.sha256).digest())
    return f"{hb}.{pb}.{sig}"


# --- decode ---

def test_decode_prints_header_and_payload(capsys):
    token = _make_token({"alg": "HS256", "typ": "JWT"}, {"user": "guest", "admin": False})
    assert main(["jwt", "decode", token]) == 0
    out = capsys.readouterr().out
    assert '"alg": "HS256"' in out
    assert '"user": "guest"' in out
    assert '"admin": false' in out


def test_decode_handles_missing_padding(capsys):
    # 페이로드 길이가 4의 배수가 아니라 '=' 패딩이 생략된 경우도 디코드돼야 한다
    token = _make_token({"alg": "none"}, {"a": 1})
    assert main(["jwt", "decode", token]) == 0
    err = capsys.readouterr().err
    assert "alg=none" in err


def test_decode_verify_correct_secret(capsys):
    token = _make_token({"alg": "HS256"}, {"x": 1}, secret=b"s3cr3t")
    assert main(["jwt", "decode", token, "--verify", "s3cr3t"]) == 0
    assert "유효함" in capsys.readouterr().err


def test_decode_verify_wrong_secret(capsys):
    token = _make_token({"alg": "HS256"}, {"x": 1}, secret=b"s3cr3t")
    assert main(["jwt", "decode", token, "--verify", "wrong"]) == 1
    assert "불일치" in capsys.readouterr().err


def test_decode_reads_token_from_stdin(capsys, monkeypatch):
    # 다른 명령처럼 토큰을 stdin 으로도 받아야 한다 (파이프 연동)
    token = _make_token({"alg": "none"}, {"user": "guest"})
    import io
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(token.encode())))
    assert main(["jwt", "decode"]) == 0
    assert '"user": "guest"' in capsys.readouterr().out


def test_decode_verify_hex_secret(capsys):
    # '0x' 접두사 시크릿(바이너리 키)도 받아야 한다
    token = _make_token({"alg": "HS256"}, {"x": 1}, secret=b"\x00\xff\x10")
    assert main(["jwt", "decode", token, "--verify", "0x00ff10"]) == 0
    assert "유효함" in capsys.readouterr().err


def test_decode_rejects_non_jwt(capsys):
    assert main(["jwt", "decode", "not-a-jwt"]) == 1
    assert "JWT 형식" in capsys.readouterr().err


# --- forge ---

def test_forge_none_strips_signature(capsys):
    token = _make_token({"alg": "HS256"}, {"admin": False}, secret=b"key")
    assert main(["jwt", "forge", token, "--alg", "none", "--set", "admin=true"]) == 0
    forged = capsys.readouterr().out.strip()
    assert forged.endswith(".")                       # 서명 조각이 비어 있음
    # 변조된 토큰을 다시 디코드하면 admin 이 true (JSON bool) 여야 한다
    assert main(["jwt", "decode", forged]) == 0
    assert '"admin": true' in capsys.readouterr().out


def test_forge_from_scratch_sets_claims(capsys):
    assert main(["jwt", "forge", "--alg", "none", "--set", "role=admin", "--set", "id=7"]) == 0
    forged = capsys.readouterr().out.strip()
    assert main(["jwt", "decode", forged]) == 0
    out = capsys.readouterr().out
    assert '"role": "admin"' in out                    # JSON 파싱 실패 -> 문자열
    assert '"id": 7' in out                            # JSON 파싱 성공 -> 정수


def test_forge_resign_hs256_is_verifiable(capsys):
    # 시크릿을 아는 상태(키 혼동 등)에서 재서명하면 그 시크릿으로 검증에 통과해야 한다
    assert main(["jwt", "forge", "--alg", "HS256", "--secret", "mykey", "--set", "admin=true"]) == 0
    forged = capsys.readouterr().out.strip()
    assert main(["jwt", "decode", forged, "--verify", "mykey"]) == 0
    assert "유효함" in capsys.readouterr().err


def test_forge_hs_requires_secret(capsys):
    assert main(["jwt", "forge", "--alg", "HS256", "--set", "a=1"]) == 1
    assert "재서명이 필요" in capsys.readouterr().err


def test_forge_set_without_equals_errors(capsys):
    assert main(["jwt", "forge", "--alg", "none", "--set", "broken"]) == 1
    assert "KEY=VALUE" in capsys.readouterr().err


# --- crack ---

def test_crack_finds_secret(tmp_path, capsys):
    token = _make_token({"alg": "HS256"}, {"u": "a"}, secret=b"letmein")
    wl = tmp_path / "words.txt"
    wl.write_text("foo\nbar\nletmein\nbaz\n", encoding="utf-8")
    assert main(["jwt", "crack", token, "-w", str(wl)]) == 0
    assert "letmein" in capsys.readouterr().out


def test_crack_not_found(tmp_path, capsys):
    token = _make_token({"alg": "HS256"}, {"u": "a"}, secret=b"letmein")
    wl = tmp_path / "words.txt"
    wl.write_text("foo\nbar\n", encoding="utf-8")
    assert main(["jwt", "crack", token, "-w", str(wl)]) == 1
    assert "찾지 못함" in capsys.readouterr().err


def test_crack_rejects_non_hs(tmp_path, capsys):
    token = _make_token({"alg": "none"}, {"u": "a"})
    wl = tmp_path / "words.txt"
    wl.write_text("foo\n", encoding="utf-8")
    assert main(["jwt", "crack", token, "-w", str(wl)]) == 1
    assert "HS 계열" in capsys.readouterr().err
