# ctfkit

워게임 학습을 위한 CTF 보조 도구입니다.
인코딩 해독, 고전 암호, 해시, RSA, JWT, 파일 분석, 바이너리 보호 기법 확인, HTTP 요청처럼
CTF 풀이에서 반복되는 작업을 **명령 하나**로 처리합니다.

pwntools·CyberChef·Ghidra 를 대체하지 않고, 그 위에서 매 문제마다 반복하는 일을 자동화합니다.

- **자동으로 풀리는 문제는 자동으로 풉니다.** 여러 겹 인코딩, 고전 암호, 약한 RSA, 파일 안에 숨긴 플래그.
- **사람도 AI 에이전트도 씁니다.** 그래픽 화면(`ctfkit ui`)과, 에이전트가 쓰기 좋은 짧은 출력·안내서·종료 코드.
- **주장하지 않고 측정합니다.** 얼마나 푸는지, 얼마나 아끼는지를 벤치마크로 재고 그 수치를 보면서 고쳤습니다.

| 측정 | 이전 | 지금 |
| --- | --- | --- |
| 자동 해독 해결률 (문제 375개) | 30% | **91%** |
| 플래그가 없는 입력에서 플래그를 지어낸 횟수 (72개 중) | | **0** |
| 에이전트의 합계 토큰 (직접 짠 코드 대비) | | **-66%** |
| 쓸 명령을 찾는 비용 (`-h` 를 읽는 것 대비) | | **-83%** |

![ctfkit 데모](docs/demo.gif)

> 데모는 로컬 테스트 서버와 직접 만든 예제 파일을 대상으로 한 실제 명령 출력입니다.

## 목차

- [빠른 시작](#빠른-시작)
- [기능](#기능)
- [사용 예시](#사용-예시)
- [그래픽 화면](#그래픽-화면)
- [AI 에이전트와 함께 쓰기](#ai-에이전트와-함께-쓰기)
- [벤치마크](#벤치마크)
- [구조와 확장](#구조와-확장)
- [개발](#개발)
- [사용 범위와 윤리](#사용-범위와-윤리)
- [참고한 도구](#참고한-도구)
- [라이선스](#라이선스)

## 빠른 시작

Python 3.10 이상이 필요합니다. PyPI 에는 배포하지 않았으므로 저장소에서 설치합니다.

```bash
git clone https://github.com/Seobyeong/ctfkit.git
cd ctfkit
pip install .
```

기본 설치만으로 모든 명령이 파이썬 표준 라이브러리로 동작합니다. 두 기능만 추가 설치가 필요합니다.

```bash
pip install ".[image]"   # forensic lsb (이미지 LSB 추출, Pillow)
pip install ".[rev]"     # rev disasm · pwn rop (디스어셈블, capstone)
```

설치했으면 바로 써 볼 수 있습니다.

```bash
ctfkit start chall.zip                    # 문제 파일 하나로 시작: 폴더·압축 풀기·분석·노트
ctfkit auto "NjY2YzYxNjc3YjY4Njk3ZA=="   # 여러 겹 인코딩 자동 해독 → flag{hi}
ctfkit guide                              # 받은 것에 맞는 명령을 한 화면으로 안내
ctfkit ui                                 # 그래픽 화면
```

## 기능

| 분야 | 명령 | 하는 일 |
| --- | --- | --- |
| 시작 | `start` | 문제 시작: 작업 폴더 생성, 압축 풀기(중첩 포함), 모든 파일 분석, 노트 작성을 한 번에 |
| | `guide` | "받은 것 → 쓸 명령" 을 한 화면으로 안내 |
| | `triage` | 파일 하나를 한 번에 분석: 형식·플래그·숨은 파일·ZIP 내용·EXIF·보호 기법 |
| | `auto` | 여러 겹으로 인코딩된 글자를 자동으로 풀어 플래그까지의 경로를 찾음 |
| 암호·인코딩 | `codec` | 인코딩/디코딩 26종: base64/58/32/85·ascii85, hex, 2진·8진·10진 코드, URL, HTML 엔티티, 이스케이프, quoted-printable, 모스 부호, A1Z26, gzip·zlib, ROT13·ROT47, 시저, 아트배시, 뒤집기, 레일 펜스, 비즈네르, XOR |
| | `crack` | 키 없이 고전 암호 해독 (시저, 비즈네르, 레일 펜스, 반복 키 XOR) |
| | `rsa` | 약한 RSA: 소인수분해, 복호, 비너(작은 d), 공통 모듈러스 |
| | `crypto` | 블록 암호 바이트 조작 (CBC 비트플립, PKCS7 패딩) |
| | `hash` | 해시 종류 판별, 사전 공격, 계산, HMAC |
| | `base` | 진법 변환 (2/8/10/16, `0x`·`0o`·`0b` 자동 인식) |
| 파일·바이너리 | `forensic` | 형식 판별, 문자열, 숨은 파일, EXIF, ZIP 목록, pcap 문자열, 이미지 LSB |
| | `rev` | ELF/PE 아키텍처·섹션·심볼 요약, 디스어셈블 |
| | `pwn` | 보호 기법 확인(checksec), cyclic 패턴·오프셋, ROP 가젯 |
| | `template` | 풀이 스크립트 뼈대: pwntools(보호 기법·아키텍처 채움), requests, RSA (생성만, 실행하지 않음) |
| 웹 | `web` | HTTP 요청, curl 재현, 퍼징, 접두사 오라클, CBC 패딩 오라클, 응답 비교 |
| | `jwt` | JWT 디코드, `alg:none`·재서명 변조, HS256 시크릿 사전 공격 |
| 작업 | `workspace` | 문제별 작업 폴더, 명령 기록, 풀이 노트 |
| | `config` | 대회별 설정: 플래그 형식, 허용 호스트 (대회 폴더의 `.ctfkit.json`) |
| | `doctor` | 외부 도구(file, strings, exiftool, binwalk, zsteg, checksec, tshark) 설치 상태 확인 |
| | `ui` | 위 명령을 모두 쓸 수 있는 그래픽 화면 |

명령별 옵션과 예시는 [docs/USAGE.md](docs/USAGE.md)에 정리했습니다.

## 사용 예시

아래 출력은 모두 실제 실행 결과입니다. 토큰과 RSA 값은 설명용으로 직접 만든 것입니다.

### 문제 파일을 받았을 때

`start` 하나로 작업 폴더를 만들고, 압축을 풀고(안의 압축까지), 모든 파일을 분석하고, 무엇을 봤는지 노트에 적습니다.
아래는 zip 안의 tar.gz 안에 Base64 와 hex 로 두 번 인코딩된 메모가 있던 경우입니다.

```
$ ctfkit start chall.zip
플래그: DH{nested_archive_flag}  [extracted/chall.zip/data/inner.tar.gz.d/secret/memo.txt · 파일 본문 (base64→hex)]
작업 폴더: .\chall
파일 5개 (압축 2개 풂)
  files/chall.zip: zip 압축 → 2개 풂
  extracted/chall.zip/data/inner.tar.gz: tar 압축 → 2개 풂
  extracted/chall.zip/readme.txt: 글자 파일 (14 바이트) | 내용 find the flag
  extracted/chall.zip/data/inner.tar.gz.d/secret/memo.txt: 글자 파일 (64 바이트) | 내용 NDQ0ODdiNmU2NTczNzQ2NTY0NWY2MTcyNjM2ODY5NzY2NTVmNjY2YzYxNjc3ZA==
  extracted/chall.zip/data/inner.tar.gz.d/secret/pic.png: PNG 이미지 (208 바이트)
노트: .\chall\notes.md
```

- 원본은 `files/` 에 복사해 두고 건드리지 않습니다. 풀린 파일은 `extracted/` 에 들어갑니다.
- 플래그를 못 찾으면 파일 형식에 맞는 다음 명령을 알려 주고, 같은 내용을 `notes.md` 에 적어 둡니다.
- **남이 만든 압축 파일을 그대로 믿지 않습니다.** 폴더 밖에 쓰려는 항목(`../`), 지나치게 크게 풀리는 항목(압축 폭탄),
  링크 파일은 풀지 않고 건너뛴 이유를 알려 줍니다. 암호가 걸린 항목도 풀지 않고 알려 줍니다.

### 인코딩된 글자를 받았을 때

```
$ ctfkit auto "NjY2YzYxNjc3YjY4Njk3ZA=="
[+] 플래그 발견 (2단계)
  [1] base64                 -> 666c61677b68697d
  [2] hex                    -> flag{hi}
flag{hi}

$ ctfkit codec decode base64 "ZmxhZ3toZWxsb30="
flag{hello}
```

### 파일 하나를 살펴볼 때

`triage` 하나로 형식 확인, 플래그 검색, 숨은 파일 탐지, ZIP 내용 확인을 한 번에 합니다.
아래는 PNG 뒤에 붙은 ZIP 안의 메모가 Base64 로 인코딩돼 있던 경우입니다.

```
$ ctfkit triage memo.png
플래그: DH{zip_then_base64}  [ZIP:memo.txt (base64)]
형식: PNG 이미지 (4249 바이트)
숨은 파일: 0x1008 ZIP
ZIP: memo.txt(29)
```

플래그를 찾지 못하면 다음에 해 볼 명령을 알려 줍니다.

```
$ ctfkit triage empty.png
[-] 플래그를 찾지 못했습니다. 아래 요약과 '다음' 줄을 참고하세요.
형식: PNG 이미지 (308 바이트)
다음: forensic lsb <파일> / forensic strings <파일> --grep <정규식>
```

설치된 외부 도구가 있으면 `triage`·`start` 가 함께 돌리고, 출력에서 플래그와 눈에 띄는 줄만 추립니다.
도구가 낸 결과에는 도구 이름이 붙습니다. 없어도 내장 구현으로 동작하고, 무엇을 설치하면 더 볼 수 있는지 한 줄로 알려 줍니다.

```
$ ctfkit triage app.exe          # strings 가 있으면 UTF-16 문자열 속 플래그까지
플래그: DH{wide_string_flag}  [strings -el (UTF-16)]
$ ctfkit doctor                   # 어떤 도구가 있고, 없으면 무엇을 못 하는지
```

| 도구 | 쓰는 곳 | 없을 때 |
| --- | --- | --- |
| `file` | 내장 표에 없는 형식 판별 | 내장 매직 바이트 표 |
| `strings` | UTF-16 문자열 속 플래그 | 내장 구현 (1바이트 문자만) |
| `exiftool` | 메타데이터 (PNG·PDF·문서 포함) | 내장 EXIF 파서 (JPEG·TIFF 만) |
| `binwalk` | 숨은 파일 탐지 | 내장 시그니처 8종 |
| `zsteg` | PNG·BMP LSB 조합 탐색 | `forensic lsb` (Pillow) |
| `checksec` | 내장 파서가 못 읽은 ELF 의 보호 기법 | 내장 ELF 파서 |
| `tshark` | pcap·pcapng 프로토콜 요약 | `forensic pcap` |

외부 도구는 시간 제한(10초)과 출력 상한(1MB)을 두고 실행합니다. `--no-external` 이나 `CTFKIT_NO_EXTERNAL=1` 로 끌 수 있습니다.

단계를 하나씩 보고 싶으면 `forensic` 의 개별 명령을 씁니다.

```
$ ctfkit forensic carve memo.png
[+] 숨은 파일 시그니처 1개:
  오프셋 0x1008 (4104)  ZIP
```

### 암호·해시

```
# 키 없이 시저 암호 해독 (영어 빈도와 가까운 순)
$ ctfkit crack caesar "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj" -n 2
key                score  result
3                   0.62  The quick brown fox jumps over the lazy dog
9                   0.61  Nby kocwe vliqh zir dogjm ipyl nby futs xia

# 해시 종류 판별 후 사전 공격
$ ctfkit hash id 5f4dcc3b5aa765d61d8327deb882cf99
가능한 종류 (3): md5, md4, ntlm
$ ctfkit hash crack 5f4dcc3b5aa765d61d8327deb882cf99 -w words.txt
[+] 찾음: password  (md5, 3개 시도)

# 약한 RSA: 소인수가 가까운 n 을 분해해 평문 복구
$ ctfkit rsa decrypt -n 1208925852309707152975447 -e 65537 -c 298898839777870285982038
[+] 분해 성공: 1099511640127 * 1099511645161
m (hex) = 0x666c61677b7273617d
m (int) = 1889377532527110218109
m (bytes) = flag{rsa}
```

### 웹·JWT

```
# JWT 를 alg:none 으로 바꿔 admin 값을 변조한 토큰 생성
$ ctfkit jwt forge eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJhZG1pbiI6ZmFsc2V9.7Mc4Ujc5fz2145BmF6Q2f-zwslS_RkT5Kn_2x6YxWxg --alg none --set admin=true
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiZ3Vlc3QiLCJhZG1pbiI6dHJ1ZX0.

# 브라우저에서 복사한 curl 명령을 그대로 재현 (쿠키 유지)
$ ctfkit web curl "curl -X POST -d 'user=admin' http://localhost:8000/login" --cookies jar.txt

# 파라미터 퍼징 (허용된 호스트에만, 속도 제한 내장)
$ ctfkit web fuzz "http://localhost:8000/?id=FUZZ" --words ids.txt --hide 404
```

### 바이너리

```
# 버퍼 오버플로 오프셋: 크래시 때 레지스터 값으로 역산
$ ctfkit pwn cyclic -l 0x61616166
20

$ ctfkit pwn checksec chall          # NX / PIE / Canary / RELRO
$ ctfkit rev info chall --sections   # 아키텍처, 섹션, 함수 심볼

# 풀이 스크립트 뼈대: 분석한 값(ARCH, PIE, CANARY, NX, RELRO)과 단서가 채워진 pwntools 스크립트
$ ctfkit template pwn chall --port 31337 > solve.py
$ ctfkit template rsa -n N -e 3 -c C > rsa.py     # 표준 라이브러리만으로 도는 풀이 (작은 e, 페르마)
```

## 그래픽 화면

명령어를 외우지 않아도 되도록 Tkinter 화면을 제공합니다. 추가 설치 없이 실행됩니다
(Linux 에서 Tkinter 가 없으면 `python3-tk` 패키지를 설치하세요).

```bash
ctfkit ui
```

![ctfkit 그래픽 화면](docs/ui.png)

- **처음이라면 예시 채우기.** 글자를 입력받는 화면마다 바로 실행되는 예시가 들어 있습니다.
- **필수 항목만 먼저 보입니다.** 명령은 분야별로 묶여 있고, 자주 쓰지 않는 옵션은 "옵션 더 보기" 로 접혀 있습니다.
- **빠뜨린 항목을 알려 줍니다.** 실행 버튼 옆에 무엇이 빠졌는지 표시하고, 그 입력 칸을 붉게 강조해 커서를 옮깁니다.
- **플래그를 따로 보여 줍니다.** 결과에서 플래그를 찾으면 결과 위에 크게 표시하고 한 번에 복사합니다.
- **결과는 화면마다 따로 보관합니다.** 다른 도구를 보다가 돌아와도 결과가 그대로 있고,
  "다른 도구로 보내기" 로 결과를 다음 도구의 입력에 바로 넣을 수 있습니다.
- **같은 동작의 CLI 명령을 함께 보여 줍니다.** 복사해서 터미널이나 스크립트에 그대로 쓸 수 있습니다.
- 항목 이름에 마우스를 올리면 기본값과 입력 형식 설명이 뜹니다.
- 단축키: `Ctrl+Enter` 실행, `Esc` 중지, `Ctrl+L` 지우기.
- 작업은 별도 프로세스에서 돌아가므로 퍼징처럼 오래 걸려도 화면이 멈추지 않습니다.

화면은 CLI 의 argparse 정의에서 자동으로 만들어집니다. 명령이나 옵션을 추가하면 화면에도 바로 나타납니다.

## AI 에이전트와 함께 쓰기

Claude Code 같은 에이전트에게 CTF 문제를 풀게 할 때, 지시문에 한 줄만 추가하면 됩니다.

```
ctfkit 이 설치돼 있다. 먼저 `ctfkit guide` 를 실행해 쓸 수 있는 명령을 확인하고, 명령에는 -q 를 붙여라.
```

에이전트가 쓰기 좋도록 만든 장치는 네 가지입니다.

**1. `guide`: 한 화면 안내서.** 처음 보는 도구라면 에이전트는 `-h` 를 여러 번 읽어 명령을 찾습니다.
`guide` 는 "받은 것 → 쓸 명령" 을 약 370 토큰에 담아 그 과정을 한 번으로 줄입니다.

```
$ ctfkit guide
ctfkit -q CMD ...   stdout=답만. 입력: 인자 | -f FILE | stdin. 세부 옵션: CMD -h
exit: 0 찾음 / 1 못 찾음 / 2 오류

파일(종류 모름)   triage FILE  # 형식·플래그·숨은 파일·ZIP 내용·EXIF·보호 기법 (--json)
인코딩된 글자     auto DATA  # 여러 겹 자동, 플래그만 출력
인코딩 지정       codec decode|encode NAME DATA [-k KEY]  # 이름: codec list
...
```

**2. `-q`: 답만 출력.** stdout 은 최종 답, stderr 는 진행·안내입니다. `-q` 를 주면 안내와 머리글이 사라지고 답만 남습니다.

```
$ ctfkit -q auto "NjY2YzYxNjc3YjY4Njk3ZA=="
flag{hi}

$ ctfkit -q triage memo.png
DH{zip_then_base64}
```

**3. 종료 코드.** 출력을 읽지 않고도 결과를 구분할 수 있습니다.

| 코드 | 뜻 | 예 |
| --- | --- | --- |
| 0 | 찾았다 | 플래그 발견, 사전 공격 성공 |
| 1 | 실행은 됐지만 찾는 것이 없다 | 플래그 없음, 사전에 없음 |
| 2 | 오류 | 잘못된 입력, 없는 파일, 사용법 오류 |

**4. 출력 상한과 JSON.** 대량 출력(`forensic strings`·`pcap`)은 기본 200줄까지만 나오고,
`--grep REGEX` 로 맞는 줄만 고를 수 있습니다. 잘리면 `-q` 여도 stderr 에 `... +N` 으로 알립니다.
`triage --json` 은 결과를 JSON 한 줄로 냅니다.

```
$ ctfkit triage memo.png --json
{"flags":[{"flag":"DH{zip_then_base64}","where":"ZIP:memo.txt (base64)"}],"info":{"형식":"PNG 이미지 (4249 바이트)","숨은 파일":"0x1008 ZIP","ZIP":"memo.txt(29)"}}
```

ctfkit 은 AI API 를 직접 호출하지 않습니다. 에이전트가 쓰는 도구이지 에이전트가 아니므로, API 키나 비용 없이 쓸 수 있습니다.

## 벤치마크

두 가지를 잽니다. **얼마나 푸는가**(해결률)와 **얼마나 아끼는가**(에이전트의 토큰·시간).
둘 다 API 키 없이 누구나 재현할 수 있습니다.

```bash
python bench/solve.py   # 해결률
python bench/run.py     # 토큰·시간
```

### 해결률

인코딩과 암호 43종을 한 겹·두 겹·세 겹으로 씌운 문제 375개를 자동으로 만들고, `auto` 가 플래그까지 푸는 비율을 잽니다.
문제는 ctfkit 코드를 쓰지 않고 표준 라이브러리로 따로 만듭니다. 맨 위 결과의 플래그가 정확히 같아야 정답입니다.

| 구분 | v0.24 | v0.25 |
| --- | --- | --- |
| 한 겹 (215문제) | 32% | 86% |
| 두 겹 (100문제) | 36% | 100% |
| 세 겹 (60문제) | 13% | 95% |
| 전체 (375문제) | 30% | **91%** |
| 오탐: 플래그가 없는 입력 72개에서 플래그를 찾았다고 한 것 | (측정 전) | **0개** |
| 문제당 시간 (95% 구간) | 17.45초 | 0.04초 |
| 벤치마크 전체 실행 시간 | 21분 | 4초 |

- v0.24 까지는 토큰 비용만 쟀고 해결률은 재지 않았습니다. 재 보니 흔한 인코딩 대부분을 풀지 못했습니다.
- v0.25 에서 변환 13종을 추가하고(2진수, 10진·8진 코드, 모스 부호, 뒤집기, ROT47, 아트배시, 레일 펜스, HTML 엔티티,
  이스케이프, quoted-printable, gzip, zlib), 탐색 규칙을 고쳤습니다.
- **느렸던 이유는 따로 있었습니다.** 탐색 시간의 85%가 비즈네르 키 추정에 쓰이고 있었습니다. 숫자나 이스케이프
  문자열에도 매번 시도했기 때문입니다. 알파벳이 절반 이상인 데이터에만 시도하도록 고쳤습니다.
- **변환을 늘리자 가짜 플래그가 나왔습니다.** 평범한 문장에 글자 암호를 다섯 번 겹쳐 `dh{...}` 모양을 만들어 내는 식입니다.
  그래서 플래그가 없는 입력도 벤치마크에 넣었고, 의미 없는 조합(같은 암호 연달아 두 번, 글자 암호 세 겹 등)을 탐색에서 잘라 냈습니다.
- **아직 못 푸는 것:** base62, base45, uuencode, 아핀 암호, 베이컨 암호, 4바이트 XOR 키. 표에서 빼지 않고 남겨 둡니다.

인코딩별 결과는 [bench/SOLVE.md](bench/SOLVE.md)에 있습니다.

### 토큰·시간

에이전트가 도구 없이 문제를 풀면 풀이 코드를 직접 쓰고 결과를 읽는 일을 반복합니다.
ctfkit 이 그 비용을 얼마나 줄이는지 과제 14개로 측정했습니다. 비교 대상은 **파이썬 표준 라이브러리만으로 짠 풀이 코드**입니다.

#### 과제를 푸는 비용

| 지표 (14개 과제 합계) | 직접 짠 코드 | ctfkit v0.29 | 변화 |
| --- | --- | --- | --- |
| 호출 수 (왕복) | 22 | 15 | -32% |
| 작성 토큰 (에이전트가 쓰는 명령·코드) | 1248 | 367 | -71% |
| 읽기 토큰 (에이전트가 읽는 출력) | 213 | 127 | -40% |
| 합계 토큰 | 1461 | 494 | -66% |
| 실행 시간 | 2.67초 | 3.00초 | +12% |

효과가 가장 큰 과제는 cyclic 오프셋(-89%)과 비즈네르 해독(-87%), 가장 작은 과제는 Base64 한 겹(-34%)입니다.
과제별 결과는 [bench/RESULTS.md](bench/RESULTS.md)에 있습니다.

#### 명령을 찾는 비용

위 표는 "어떤 명령을 쓸지 이미 안다" 고 가정합니다. 처음 보는 도구에서는 그 전에 명령을 찾는 비용이 듭니다.
14개 과제에 쓰는 명령 11개를 찾는 비용입니다.

| 방법 | 호출 수 | 합계 토큰 |
| --- | --- | --- |
| `-h` 를 따라 내려가기 (`ctfkit -h` → `ctfkit hash -h` → `ctfkit hash crack -h` ...) | 18 | 2181 |
| `ctfkit guide` 한 번 | 1 | 372 |
| 변화 | -94% | -83% |

#### 처음부터 좋았던 것은 아닙니다

처음 쟀을 때(v0.19)는 쓰는 양만 줄고, **읽는 양과 실행 시간은 직접 짠 코드보다 나빴습니다.**
측정으로 드러난 약점을 한 버전에 하나씩 고쳤습니다.

| 버전 | 고친 것 | 합계 토큰 | 읽기 토큰 | 실행 시간 |
| --- | --- | --- | --- | --- |
| v0.19 | (처음 측정) | -37% | +66% | +109% |
| v0.21 | `-q` 를 주면 답만 출력 | -56% | -20% | +124% |
| v0.22 | 실행할 명령의 모듈만 불러오기 | -56% | -20% | +15% |
| v0.23 | 파일 분석을 한 번에 묶는 `triage` | -66% | -40% | +3% |
| v0.24 | 한 화면 안내서 `guide`, 종료 코드 정리 | (명령을 찾는 비용 -83%) | | |

각 단계에서 무엇을 발견하고 왜 그렇게 고쳤는지는 [개발 일지](docs/devlog.md)에 있습니다.

### 이 수치의 한계

- **해결률의 문제는 직접 만든 것입니다.** 실제 대회 문제가 아니고, 인코딩 목록도 제가 골랐습니다. 못 푸는 종류를 일부러
  넣어 두었지만 대표성이 검증된 것은 아닙니다. 실제 문제로 확인하는 것이 다음 단계입니다.
- **변환을 늘린 대가로 실행 시간이 조금 늘었습니다.** 토큰 벤치마크의 실행 시간이 +4% 에서 +12~18% 가 됐습니다.
- **토큰은 추정값입니다.** UTF-8 바이트 수를 4로 나눈 값이고, 실제 토크나이저 결과와 다릅니다.
- **모델의 비용은 재지 않습니다.** 모델이 생각하는 시간, 시스템 프롬프트, 이전 대화는 포함하지 않습니다.
- **표준 라이브러리와만 비교합니다.** pwntools 같은 전문 도구가 설치된 환경이면 비교 대상의 코드가 훨씬 짧아집니다.
- **호출 수는 목표(-40%)에 못 미쳤습니다.** 비교 코드가 풀이 방법을 미리 안다고 가정해 대부분 한 번에 끝나기 때문에,
  14개 중 호출 수가 줄어든 과제가 3개뿐입니다. 과제를 더 넣어 수치를 맞추지 않았습니다.
- **`-h` 경로의 18회는 상한에 가깝습니다.** 실제 에이전트는 필요한 도움말만 골라 읽습니다.
- **v0.23 에서 과제와 비교 코드를 바꿨습니다.** 과제를 하나 추가했고, 비교 코드 하나가 규칙보다 느슨했던 것을
  ctfkit 에 불리한 방향으로 고쳤습니다. 그래서 v0.22 이전 수치와는 기준이 조금 다릅니다.
- **실제 에이전트로는 아직 재지 않았습니다.** 드림핵 문제를 에이전트에게 풀게 해 비교하는 것이 다음 단계입니다.

측정 규칙과 비교 코드를 정한 기준은 [bench/README.md](bench/README.md)에 적었습니다.

## 구조와 확장

```
ctfkit/
├── cli.py            # 진입점. 실행할 명령의 모듈만 불러온다
├── registry.py       # 변환(Transform) 플러그인 레지스트리
├── transforms/       # 확장 지점 1: 변환 하나 = 파일 하나
├── commands/         # 확장 지점 2: 명령 하나 = 파일 하나
├── engine/           # auto 의 빔 서치와 점수 함수
├── unpack.py         # 안전한 압축 풀기 (경로 탈출·압축 폭탄·링크 차단)
├── gui/              # argparse 정의를 읽어 화면을 만든다
└── (binfmt, exif, rsautil, ngram ...)   # 파일 형식 파싱과 계산
bench/                # 벤치마크 과제와 실행기
tests/                # pytest 825개
```

변환을 하나 추가하면 `codec`·`crack`·`auto`, 그래픽 화면, 왕복 테스트에 **코드 수정 없이** 함께 나타납니다.

```python
# ctfkit/transforms/atbash.py
from ctfkit.registry import Transform, register

@register
class Atbash(Transform):
    name = "atbash"
    description = "알파벳 뒤집기 (a↔z)"

    def decode(self, data, key=None): ...
    def encode(self, data, key=None): ...
```

명령도 같은 방식입니다. `commands/` 에 `register(subparsers)` 를 가진 파일을 두면 CLI 와 화면에 붙습니다.
자세한 설명은 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)를 참고하세요.

## 개발

```bash
pip install -e ".[dev]"
pytest                                   # 테스트 825개
pytest --cov=ctfkit --cov-report=term    # 커버리지 (CI 기준 70% 이상)
python bench/solve.py --write            # 해결률을 다시 재서 bench/SOLVE.md 갱신
python bench/run.py --write              # 토큰·시간을 다시 재서 bench/RESULTS.md 갱신
python bench/readme_check.py             # 설치된 ctfkit 으로 이 README 의 예시가 그대로 나오는지 확인
```

GitHub Actions 가 Windows·Linux 와 Python 3.10~3.13 조합에서 테스트를 돌립니다.

| 문서 | 내용 |
| --- | --- |
| [docs/USAGE.md](docs/USAGE.md) | 명령별 사용법 요약 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 코드 구조, 확장 방법, 알고리즘 설명 |
| [docs/ROADMAP.md](docs/ROADMAP.md) | 방향, 단계별 목표와 통과 조건, 알려진 한계 |
| [docs/devlog.md](docs/devlog.md) | 개발 일지: 요청한 것, 리뷰에서 발견한 것, 배운 것 |
| [docs/fieldlog.md](docs/fieldlog.md) | 실전 기록: 실제 문제를 풀며 ctfkit 이 도운 것과 막힌 것 |
| [bench/README.md](bench/README.md) | 벤치마크 측정 방법과 한계 |

## 사용 범위와 윤리

이 도구, 특히 `web`·`hash` 처럼 요청을 보내거나 값을 대입하는 기능은 **학습 목적으로만** 사용합니다.

- **허가된 대상에만 사용합니다.** 드림핵이 문제로 제공한 워게임 인스턴스, `localhost`, 직접 띄운 실습 서버만 대상으로 합니다.
- `web` 은 허용 호스트 목록(allowlist) 밖으로는 요청을 보내지 않습니다. 기본값은 `localhost` 와 `*.dreamhack.games` 입니다.
  다른 대회 서버는 사용자가 `--allow` 나 `ctfkit config add allow` 로 직접 적은 것만 더하고, 문제 파일 안의 설정 파일은 읽지 않습니다.
- 반복 요청에는 속도 제한과 총량 상한이 있습니다.
- `rev`·`pwn` 은 로컬 파일의 정적 분석과 오프셋·가젯 계산까지만 합니다. 원격 서비스 공격 자동화는 다루지 않습니다.
- 허가받지 않은 시스템에 사용하는 것은 불법일 수 있으며, 그 책임은 사용자에게 있습니다.

## 참고한 도구

설계와 아이디어 면에서 다음 도구를 참고했습니다. **이 도구들의 코드는 가져다 쓰지 않았습니다.**
ctfkit 의 코드와 테스트는 AI(Claude Code)가 작성하고 사람이 리뷰·수정 요청하는 방식으로 만들었습니다
(작업 방식은 [ROADMAP](docs/ROADMAP.md#7-개발-방식), 단계별 기록은 [개발 일지](docs/devlog.md)).
고전 암호 분석(빈도 분석, 일치 지수, 알려진 평문 공격)과 RSA 공격(페르마 분해, 비너, 공통 모듈러스)은
교과서에 나오는 방법을 구현한 것입니다.

| 도구 | 참고한 점 |
| --- | --- |
| [CyberChef](https://github.com/gchq/CyberChef) "Magic" | 여러 겹 인코딩을 자동 탐지하는 아이디어 (`auto`) |
| [Katana](https://github.com/JohnHammond/katana) | 문제 파일에 맞는 분석을 모두 돌리고 결과에 다시 적용하는 방향 (`triage`, `start`) |
| [Ciphey](https://github.com/Ciphey/Ciphey) | 점수 기반 다단계 복호화 탐색 (`auto`) |
| `curl` | HTTP 요청 인터페이스 (`web`) |
| [binwalk](https://github.com/ReFirmLabs/binwalk) | 파일 안에 숨은 파일을 찾는 방향 (`forensic`) |
| [jwt_tool](https://github.com/ticarpi/jwt_tool) | JWT 디코드·변조·공격의 범위 (`jwt`) |
| [radare2](https://github.com/radareorg/radare2), [Capstone](https://www.capstone-engine.org/) | 바이너리 요약과 디스어셈블 (`rev`). Capstone 은 선택 의존성으로 사용 |
| [pwntools](https://github.com/Gallopsled/pwntools), [checksec.sh](https://github.com/slimm609/checksec.sh), [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) | 보호 기법 확인, cyclic 패턴, 가젯 검색 (`pwn`) |

`triage`·`start` 는 binwalk, zsteg, exiftool, file, strings, checksec, tshark 가 설치돼 있으면 **실행만** 합니다
(코드를 가져오지 않고, 출력에서 플래그와 눈에 띄는 줄을 추립니다).

선택 의존성으로 쓰는 외부 라이브러리는 [Pillow](https://python-pillow.org/)(`forensic lsb`)와
[Capstone](https://www.capstone-engine.org/)(`rev disasm`, `pwn rop`) 두 가지입니다.

## 라이선스

[MIT](LICENSE)
