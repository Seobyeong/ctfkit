"""forensic 명령 테스트."""

from ctfkit.cli import main
from ctfkit.commands.forensic import extract_strings, find_embedded, identify

PNG_HEADER = b"\x89PNG\r\n\x1a\n"
ZIP_HEADER = b"PK\x03\x04"


def test_identify_png():
    assert "PNG" in identify(PNG_HEADER + b"rest")


def test_identify_unknown():
    assert identify(b"\x01\x02\x03\x04") is None


def test_extract_strings_filters_short():
    data = b"\x00ab\x00hello\x00\x01world!!\x00"
    found = [s for _, s in extract_strings(data, min_len=4)]
    assert "hello" in found
    assert "world!!" in found
    assert "ab" not in found


def test_find_embedded_zip_after_png():
    data = PNG_HEADER + b"\x00" * 20 + ZIP_HEADER + b"payload"
    found = find_embedded(data)
    assert any(name == "ZIP" for _, name in found)
    # 오프셋 0 의 PNG 자신은 숨은 파일로 세지 않는다
    assert all(off > 0 for off, _ in found)


def test_id_command(tmp_path, capsys):
    f = tmp_path / "a.png"
    f.write_bytes(PNG_HEADER + b"body")
    assert main(["forensic", "id", str(f)]) == 0
    assert "PNG" in capsys.readouterr().out


def test_id_unknown_returns_1(tmp_path, capsys):
    f = tmp_path / "a.bin"
    f.write_bytes(b"\x01\x02\x03")
    assert main(["forensic", "id", str(f)]) == 1


def test_strings_command(tmp_path, capsys):
    f = tmp_path / "a.bin"
    f.write_bytes(b"\x00flag{strings}\x00")
    assert main(["forensic", "strings", str(f)]) == 0
    assert "flag{strings}" in capsys.readouterr().out


def test_carve_detects_and_dumps(tmp_path, capsys):
    f = tmp_path / "stego.png"
    f.write_bytes(PNG_HEADER + b"\x00" * 10 + ZIP_HEADER + b"hidden")
    out = tmp_path / "out.zip"
    assert main(["forensic", "carve", str(f), "--dump", str(out)]) == 0
    assert out.read_bytes().startswith(ZIP_HEADER)
    assert "ZIP" in capsys.readouterr().out


def test_carve_nothing(tmp_path, capsys):
    f = tmp_path / "plain.png"
    f.write_bytes(PNG_HEADER + b"just image data")
    assert main(["forensic", "carve", str(f)]) == 1


def test_meta_finds_flag(tmp_path, capsys):
    f = tmp_path / "a.bin"
    f.write_bytes(b"junk DH{found_in_meta} junk")
    assert main(["forensic", "meta", str(f)]) == 0
    assert "DH{found_in_meta}" in capsys.readouterr().out


def test_missing_file(capsys):
    assert main(["forensic", "id", "no/such/file"]) == 2
    assert "오류" in capsys.readouterr().err


def test_meta_finds_flag_right_after_other_text(tmp_path, capsys):
    # 비압축 ZIP 은 파일 이름 바로 뒤에 내용이 온다: "flag.txtDH{...}"
    f = tmp_path / "stego.png"
    f.write_bytes(PNG_HEADER + b"\x00PK\x03\x04flag.txtDH{glued}PK")
    assert main(["forensic", "meta", str(f)]) == 0
    assert "DH{glued}" in capsys.readouterr().out


def test_meta_custom_flag_pattern_is_used_as_is(tmp_path, capsys):
    f = tmp_path / "a.bin"
    f.write_bytes(b"xxmyctf{a} DH{b}")
    assert main(["forensic", "meta", str(f), "--flag", r"\bmyctf\{.*?\}"]) == 0
    out = capsys.readouterr().out
    assert "DH{b}" not in out
    assert "myctf{a}" not in out   # 앞에 xx 가 붙어 \b 에 걸린다: 사용자 패턴을 그대로 쓴다는 뜻


def test_other_commands_keep_word_boundary():
    from ctfkit.flags import compile_flag_pattern, find_flag
    assert find_flag(b"myctf{cut}", compile_flag_pattern()) is None
