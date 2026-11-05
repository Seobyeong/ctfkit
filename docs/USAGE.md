# ctfkit 사용법 (치트시트)

문제를 풀 때 바로 보고 쓰는 요약. 각 명령의 전체 옵션은 `ctfkit <명령> -h`.

> 입력은 대부분 **인자 / `-f 파일` / stdin(`-` 또는 생략)** 세 가지로 받는다.
> 한글 출력이 깨지는 콘솔이면 `set PYTHONIOENCODING=utf-8`(PowerShell: `$env:PYTHONIOENCODING='utf-8'`).

---

## 1. codec — 인코딩/디코딩

```bash
ctfkit codec list                       # 변환 목록 ([key] 표시는 키 필요)
ctfkit codec decode b64 "ZmxhZw=="      # 디코드
ctfkit codec encode hex "flag"          # 인코드
ctfkit codec decode xor -k 0x42 "..."   # 키 필요한 변환: -k
ctfkit codec decode caesar -k 3 "Fdhvdu"
ctfkit codec decode vigenere -k KEY "..."
ctfkit codec decode b64 -f dump.txt     # 파일 입력
echo "ZmxhZw==" | ctfkit codec decode b64   # stdin
```

변환 이름: `base64/b64`, `base32/b32`, `hex/base16`, `url/percent`, `rot13`,
`caesar`[key], `vigenere/vig`[key], `xor`[key].

## 2. auto — 여러 겹 자동 해독

```bash
ctfkit auto "NjY2YzYxNjc3YjY4Njk3ZA=="  # 자동 추정, 플래그까지 경로 출력
ctfkit auto -f blob.txt
ctfkit auto "..." --flag 'myctf\{.*?\}' # 플래그 형식 지정
ctfkit auto "..." -d 8 -b 50            # 깊이·빔 너비 늘리기(안 풀릴 때)
ctfkit auto "..." -n 5                  # 플래그 없을 때 후보 5개 보기
```

## 3. crack — 키 없이 고전 암호 해독

```bash
ctfkit crack caesar "Fdhvdu flskhu"     # 시저: 25개 중 best
ctfkit crack vigenere -f cipher.txt     # 비즈네르: 키 길이·키 추정
ctfkit crack xor "..."                  # 반복키 XOR 추정
ctfkit crack vigenere "..." -n 10        # 후보 더 보기
```
> 비즈네르는 ~250바이트 이상이면 잘 풀린다. 짧으면 키 일부가 틀릴 수 있음.

## 4. hash — 해시 판별·공격·계산

```bash
ctfkit hash id 5f4dcc3b5aa765d61d8327deb882cf99   # 종류 추정
ctfkit hash sum sha256 flag                        # 해시 계산
ctfkit hash sum md5 -f file.bin
ctfkit hash crack <해시> -w rockyou.txt            # 사전 공격(종류 자동 추정)
ctfkit hash crack <해시> -w words.txt -a sha1      # 알고리즘 지정
ctfkit hash hmac sha256 -k secret "message"        # HMAC (-k 0x.. 면 16진수 키)
```

## 5. forensic — 파일 분석

```bash
ctfkit forensic meta  file.png          # 형식·크기·플래그 한눈에 (먼저 이거부터)
ctfkit forensic id    file.bin          # 매직 바이트로 형식 판별
ctfkit forensic strings file -n 6       # 길이 6 이상 문자열
ctfkit forensic strings file --offset   # 오프셋도 같이
ctfkit forensic carve stego.png         # 뒤에 숨겨 붙인 파일 탐지
ctfkit forensic carve stego.png --dump out.zip   # 첫 숨은 파일 추출
ctfkit forensic lsb  stego.png          # LSB 추출 (저장소에서 pip install ".[image]")
ctfkit forensic lsb  stego.png -b 2      # 하위 2비트
```
> 추천 순서: `meta` → `strings`로 플래그 훑기 → `carve`로 첨부 파일 → `lsb`.

## 6. web — HTTP 요청 (allowlist·속도 제한)

```bash
ctfkit web send http://localhost:8000/
ctfkit web send http://host/login -X POST -d 'user=admin&pw=1' -H 'X-A: 1'
ctfkit web send http://host/ --cookies jar.txt --show-headers   # 쿠키 유지+헤더
ctfkit web curl "curl -X POST -d 'a=1' http://host/x"           # curl 그대로 재현
ctfkit web fuzz "http://host/?id=FUZZ" -w ids.txt --hide 404    # 퍼징
ctfkit web fuzz "http://host/" -X POST -d 'pw=FUZZ' -w pw.txt --delay 0.3 --max 500
```
- `FUZZ` 자리를 워드리스트로 치환. URL·본문 양쪽에 사용 가능.
- allowlist 밖 호스트는 차단. 허용하려면 `--allow host` (`.example.com` 처럼 접미사 가능).
- `--delay`(기본 0.5s)·`--max`(기본 200) 로 속도·총량 제한. **학습 목적·허가된 대상만.**

## 7. workspace (ws) — 문제별 작업 관리

```bash
ctfkit workspace new web-100            # 폴더 + 풀이 노트(.md) 템플릿 생성
ctfkit ws list                          # 작업 폴더 목록 (ws 는 별칭)
ctfkit ws log web-100 ctfkit web send http://host/   # 실행 명령 기록
ctfkit ws info web-100                   # 노트 경로·기록 수 요약
ctfkit ws --root ./ctf new crypto-50     # 상위 경로 지정
```

---

## 전형적인 풀이 흐름

```bash
# 1) 인코딩 문자열을 받았다
ctfkit auto "ZmxhZ3t...}="                # 안 풀리면 crack / codec 수동

# 2) 파일(이미지 등)을 받았다
ctfkit forensic meta chall.png
ctfkit forensic carve chall.png --dump hidden.zip

# 3) 해시를 받았다
ctfkit hash id <해시> && ctfkit hash crack <해시> -w rockyou.txt

# 4) 웹 문제
ctfkit web curl "curl ..."                # 브라우저/버프에서 복사한 curl 재현
ctfkit web fuzz "http://host/?p=FUZZ" -w wl.txt --hide 404

# 작업 기록을 남기며
ctfkit ws new <문제> && ctfkit ws log <문제> <실행한 명령>
```
