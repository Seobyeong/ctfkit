"""ctfkit guide: "무엇을 받았을 때 어떤 명령을 쓰는가" 를 한 화면으로 보여 준다.

AI 에이전트는 처음 보는 도구를 쓸 때 `-h` 를 여러 번 읽어 명령을 고른다 (`ctfkit -h` → `ctfkit hash -h` →
`ctfkit hash crack -h` ...). 그 탐색도 왕복이고 읽는 토큰이다. guide 는 그 과정을 한 번의 호출로 줄인다.

안내문은 짧아야 의미가 있으므로 500 토큰(UTF-8 2000바이트) 이하로 유지한다. tests/test_guide_v024.py 가
길이 상한과 "모든 명령이 안내문에 있는가" 를 검사하므로, 명령을 추가하면 여기에도 한 줄을 넣어야 한다.
"""

GUI_HINTS = {
    "guide": {"hidden": True},   # 화면에서는 사이드바가 같은 역할을 한다
}

GUIDE = """\
ctfkit -q CMD ...   stdout=답만. 입력: 인자 | -f FILE | stdin. 세부 옵션: CMD -h
exit: 0 찾음 / 1 못 찾음 / 2 오류

파일(종류 모름)   triage FILE  # 형식·플래그·숨은 파일·ZIP 내용·EXIF·보호 기법 (--json)
인코딩된 글자     auto DATA  # 여러 겹 자동, 플래그만 출력
인코딩 지정       codec decode|encode NAME DATA [-k KEY]  # 이름: codec list
암호, 키 모름     crack caesar|vigenere|xor DATA
진법              base VALUE [--to 2|8|10|16]
해시              hash id H | hash crack H -w WORDS | hash sum ALGO DATA | hash hmac ALGO -k K DATA
RSA               rsa decrypt -n N -e E -c C [-p P -q Q] | rsa wiener -n N -e E -c C | rsa factor N | rsa common-modulus -n N --e1 --c1 --e2 --c2
JWT               jwt decode T | jwt forge T --alg none --set K=V | jwt crack T -w WORDS
블록 암호         crypto cbc-flip --cipher B64 --offset N --known A --desired B | crypto pkcs7-pad|pkcs7-unpad HEX
문자열 검색       forensic strings FILE --grep REGEX [--limit N]
파일 세부         forensic meta|id|carve|exif|zip|pcap|lsb FILE
ELF/PE            pwn checksec FILE | rev info FILE | rev disasm FILE | pwn rop FILE -f 'pop rdi'
오버플로 오프셋   pwn cyclic N | pwn cyclic -l 0x6161616c
HTTP(허용 호스트) web send URL | web curl 'curl ...' | web fuzz URL -w WORDS | web oracle|padding-oracle|diff
기록              workspace new|list|log|info NAME
화면              ui
"""


def register(subparsers):
    p = subparsers.add_parser("guide", help="받은 것에 맞는 명령을 한 화면으로 안내 (AI 에이전트용 요약)")
    p.set_defaults(func=_run)


def _run(args):
    print(GUIDE, end="")
    return 0
