# ctfkit 사용법 (치트시트)

문제를 풀 때 바로 보고 쓰는 요약. 각 명령의 전체 옵션은 `ctfkit <명령> -h`.

> 입력은 대부분 **인자 / `-f 파일` / stdin(`-` 또는 생략)** 세 가지로 받는다.
> 한글 출력이 깨지는 콘솔이면 `set PYTHONIOENCODING=utf-8`(PowerShell: `$env:PYTHONIOENCODING='utf-8'`).

> **공통 옵션 / 출력 규칙:** stdout 은 최종 답, stderr 는 진행·안내다. `ctfkit -q <명령>` 으로 안내를
> 끄고 답만 얻는다(AI·파이프 전달용). 대량 출력(`forensic strings`·`pcap`)은 `--grep REGEX` 로
> 맞는 줄만, `--limit N` 으로 N 줄까지 걸러 토큰을 아낀다.

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

변환 이름: `base64/b64`, `base58/b58`, `base32/b32`, `base85/b85`, `ascii85/a85`,
`hex/base16`, `url/percent`, `rot13`, `caesar`[key], `vigenere/vig`[key], `xor`[key].
> `base85`/`ascii85` 는 거의 모든 입력이 "그럴듯하게" 풀려 `auto` 를 오염시키므로 자동 탐색에선
> 빠진다. 필요하면 `codec` 으로 직접 지정해 쓴다.

## 진법 변환 — base

```bash
ctfkit base 255                 # 2/8/10/16 진수로 한 번에 보기
ctfkit base 0xff --to 2         # 16진수 -> 2진수 (11111111)
ctfkit base 777 --from 8 --to 10   # 8진수 777 -> 10진수 (511)
```
입력은 `0x`/`0o`/`0b` 접두사를 자동 인식한다. `--from` 으로 진법을 못 박을 수 있다(2~36).

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
ctfkit crack xor "..."                  # 반복키 XOR 추정 (1·다중 바이트)
ctfkit crack xor -f cipher.bin          # 접두사 없이도 다중 바이트 키 복구
ctfkit crack vigenere "..." -n 10        # 후보 더 보기
```
> 비즈네르는 열별 빈도분석으로 시드 키를 잡은 뒤 영어 바이그램 점수로 언덕 오르기(hill climbing)를
> 해 다듬는다. ~75바이트 안팎까지 키를 1순위로 복구한다. 더 짧거나(키가 길면) 키 일부가 틀릴 수 있다.
>
> XOR 은 플래그 접두사(알려진 평문)가 있으면 바로 키를 구하고, 없으면 해밍 거리로 키 길이를 추정해
> 다중 바이트 반복 키도 복구한다. 데이터가 길수록 더 긴 키까지 복구된다(~500바이트에 10바이트 키).

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
ctfkit forensic strings file --grep "DH\{"  # 플래그 후보만 (토큰 절약)
ctfkit forensic strings file --limit 50     # 앞 50줄만 (나머지 개수는 stderr 안내)
ctfkit forensic carve stego.png         # 뒤에 숨겨 붙인 파일 탐지
ctfkit forensic carve stego.png --dump out.zip   # 첫 숨은 파일 추출
ctfkit forensic exif  photo.jpg         # EXIF/TIFF 메타데이터 (Author/Comment/GPS 등)
ctfkit forensic zip   archive.zip       # ZIP 안 파일 목록 (뒤에 붙은 ZIP 도 읽음)
ctfkit forensic pcap  capture.pcap      # 패킷 페이로드에서 문자열 추출
ctfkit forensic lsb  stego.png          # LSB 추출 (저장소에서 pip install ".[image]")
ctfkit forensic lsb  stego.png -b 2 -c r   # 하위 2비트, R 채널만
```
> 추천 순서: `meta` → `strings`로 플래그 훑기 → `exif`로 메타데이터 → `carve`/`zip`으로 첨부 파일 → `lsb`.
> `exif`·`zip`·`pcap` 은 외부 의존성 없이 동작한다(파싱을 직접 구현). pcap 은 classic pcap 만 지원(pcapng 미지원).

## 6. web — HTTP 요청 (allowlist·속도 제한)

```bash
ctfkit web send http://localhost:8000/
ctfkit web send http://host/login -X POST -d 'user=admin&pw=1' -H 'X-A: 1'
ctfkit web send http://host/ --cookies jar.txt --show-headers   # 쿠키 유지+헤더
ctfkit web curl "curl -X POST -d 'a=1' http://host/x"           # curl 그대로 재현
ctfkit web fuzz "http://host/?id=FUZZ" -w ids.txt --hide 404    # 퍼징
ctfkit web fuzz "http://host/" -X POST -d 'pw=FUZZ' -w pw.txt --delay 0.3 --max 500
ctfkit web fuzz "http://host/" -d 'pw=FUZZ' -w pw.txt --match 'FLAG'   # 본문에 FLAG 있는 응답만
ctfkit web oracle "http://host/" -d 'locker_num=FUZZ' --fail 'Wrong!'  # 접두사 오라클 자동 복구
ctfkit web padding-oracle "http://host/dec?e_data=FUZZ&token=x&sig=x" \
  --cipher <base64암호문> --bad 'ValueError' --iv 00000000000000000000000000000000
ctfkit web diff "http://host/?id=1" "http://host/?id=2"   # 두 응답 상태·길이·본문 비교
```
- `FUZZ` 자리를 워드리스트로 치환. URL·본문 양쪽에 사용 가능.
- allowlist 밖 호스트는 차단. 허용하려면 `--allow host` (`.example.com` 처럼 접미사 가능).
- `--delay`(기본 0.5s)·`--max`(기본 200) 로 속도·총량 제한. **학습 목적·허가된 대상만.**
- `fuzz --match REGEX` / `--fail REGEX`: 상태코드가 아니라 **응답 본문**으로 결과를 걸러서 보여준다.
- `oracle`: `secret[0:len(guess)] == guess` 처럼 **입력 길이만큼만 비교**하는 취약점을, 한 글자씩
  (복구한 접두사 + charset 글자) 를 보내며 자동 복구한다. `--success`/`--fail` 정규식으로 "맞은 접두사"를
  판별하고, 복구한 값은 stdout 으로 출력한다 (`--charset` 기본: 소문자+숫자, `--max-length` 기본 32).
  36⁴≈168만 가지를 **36×4 번**으로 줄인다.
- `diff`: 두 URL 에 같은 메서드·헤더·본문으로 요청해 **상태코드·본문 길이·본문(라인 단위 diff)** 을 비교한다.
  파라미터 하나 바꿨을 때 응답이 어떻게 달라지는지(인젝션·권한 차이 등) 빠르게 본다.
- `padding-oracle`: CBC/PKCS7 **패딩 오라클**로 키 없이 암호문을 복호화한다. `--bad`(패딩 틀림) 또는
  `--ok`(패딩 맞음) 정규식으로 서버 응답을 판별하고, 블록 단위로 평문을 복원해 stdout 으로 출력한다.
  `--iv`(hex) 를 주면 첫 블록까지 복원(없으면 0 으로 가정). 요청이 많으므로 **허가된 대상만**.

## 7. crypto — 블록 암호 바이트 조작 (키 불필요)

```bash
ctfkit crypto cbc-flip --cipher <b64> --offset 16 --known 'user' --desired 'admn'  # CBC 비트플립
ctfkit crypto cbc-flip --cipher <b64> --offset 0 --known 'a' --desired 'b' --iv 00..00  # 첫 블록은 IV 조작
ctfkit crypto pkcs7-pad 48656c6c6f --block 16     # hex -> 패딩된 hex
ctfkit crypto pkcs7-unpad <hex> --block 16        # 패딩 떼기 (유효하지 않으면 오류)
```
- `cbc-flip`: 평문 `offset` 위치를 `known`→`desired` 로 바꾸려고 **이전 블록(또는 IV)** 바이트를 XOR 조작한다.
  바뀐 이전 블록의 평문은 깨지므로, 보통 버려도 되는 블록(IV 등)을 대상으로 쓴다.
- 표준 라이브러리만 사용한다. 키/IV 를 알 때의 AES 직접 암복호화는 포함하지 않는다.

## 7-2. rsa — 약한 RSA 공격 (로컬 계산)

```bash
ctfkit rsa factor <n>                                   # n 소인수분해(페르마/폴라드로/시험)
ctfkit rsa decrypt -n <n> -e <e> -c <c>                 # n 분해 → d 계산 → 평문 복구
ctfkit rsa decrypt -n <n> -e <e> -c <c> -p <p> -q <q>   # p,q 를 알면 분해 생략
ctfkit rsa wiener -n <n> -e <e> -c <c>                  # 작은 개인 지수 d 복구(연분수)
ctfkit rsa common-modulus -n <n> --e1 <e1> --c1 <c1> --e2 <e2> --c2 <c2>  # 같은 n·서로소 e
```
- 숫자는 10진수 또는 `0x..` 로 준다. 평문은 정수·16진수·바이트로 보여 준다.
- `factor` 는 **약한 n 만** 분해된다: 소인수가 가깝거나(페르마) 작은 소인수가 있을 때. 큰 임의
  소수 두 개로 만든 강한 n 은 분해되지 않으며, 그때는 `-p -q` 로 직접 지정한다.
- `wiener` 는 대략 `d < n^0.25 / 3` 일 때 성공한다.
- 로컬 계산만 한다 — 주어진 파라미터로 분해·복구할 뿐 원격 서비스를 공격하지 않는다(학습 목적).

## 8. jwt — JWT 디코드·변조·시크릿 공격

```bash
ctfkit jwt decode <token>                             # 헤더·페이로드 디코드
ctfkit jwt decode <token> --verify s3cr3t             # HS 서명까지 검증
ctfkit jwt forge <token> --alg none --set admin=true  # alg:none 으로 서명 없는 변조 토큰
ctfkit jwt forge --alg HS256 --secret key --set role=admin  # 시크릿 알 때 재서명(빈 페이로드부터)
ctfkit jwt crack <token> -w rockyou.txt               # HS256 시크릿 사전 공격
cat token.txt | ctfkit jwt decode                     # 토큰은 stdin 으로도 받는다('-' 생략 가능)
```
- `--set KEY=VALUE` 값은 JSON 으로 먼저 해석한다: `admin=true`→불리언, `id=7`→정수, `role=admin`→문자열.
- `forge` 에 기준 토큰을 주면 그 헤더·페이로드를 이어받아 수정하고, 생략하면 `{"typ":"JWT"}` 빈 페이로드부터 시작한다.
- 표준 라이브러리만 사용한다. 대칭키(HS256/384/512)만 지원하고, 비대칭(RS/ES)은 개인키가 필요해 뺐다.

## 9. rev — 실행 파일(ELF/PE) 정적 분석

```bash
ctfkit rev info  chall            # 아키텍처·엔디언·entry·섹션/심볼 개수 + 함수 심볼
ctfkit rev info  chall --sections # 섹션 목록(주소·오프셋·크기)도 함께
ctfkit rev disasm chall           # entry 부터 32개 명령 디스어셈블 (capstone 필요)
ctfkit rev disasm chall --offset 0x401000 -n 10   # 가상주소부터 10개
ctfkit rev disasm chall --offset +0x40            # 파일 오프셋(+)부터
```
- `info` 는 표준 라이브러리만으로 ELF32/64(LE/BE)·PE32/PE32+ 를 파싱한다.
- `disasm` 은 capstone 이 있어야 한다: `pip install ".[rev]"` (또는 `pip install capstone`).
- 로컬 파일 정적 분석까지만 한다. 원격 서비스 익스플로잇은 다루지 않는다.

## 10. pwn — 포너블 보조 (보호 기법·cyclic·ROP)

```bash
ctfkit pwn checksec chall           # NX/PIE/Canary/RELRO (PE 는 DEP/ASLR/CFG)
ctfkit pwn cyclic 200               # de Bruijn 패턴 200바이트 생성
ctfkit pwn cyclic -l 0x6161616c     # 크래시 때 레지스터 값(리틀엔디언)으로 오프셋 역산
ctfkit pwn cyclic -l faaa           # 또는 패턴에서 본 4글자로
ctfkit pwn rop chall -f 'pop rdi'   # ret 로 끝나는 가젯 중 'pop rdi' 포함만 (capstone 필요)
```
- `checksec`·`cyclic` 은 표준 라이브러리만으로 동작한다(ELF/PE 파싱은 `rev` 와 공용인 `binfmt`).
- `rop` 은 capstone 이 있어야 하고 x86/x64 ELF 를 대상으로 한다: `pip install ".[rev]"`.
- cyclic 기본 부분열 길이는 4(32비트 워드). 64비트는 `-n 8` 로 늘린다.
- 로컬 파일 정적 분석과 오프셋·가젯 계산까지만 한다. 익스플로잇 자동화는 다루지 않는다.

## 11. workspace (ws) — 문제별 작업 관리

```bash
ctfkit workspace new web-100            # 폴더 + 풀이 노트(.md) 템플릿 생성
ctfkit ws list                          # 작업 폴더 목록 (ws 는 별칭)
ctfkit ws log web-100 ctfkit web send http://host/   # 실행 명령 기록
ctfkit ws info web-100                   # 노트 경로·기록 수 요약
ctfkit ws --root ./ctf new crypto-50     # 상위 경로 지정
```

---

## 12. ui — 그래픽 화면

```bash
ctfkit ui                               # 위의 모든 명령을 화면에서 실행
```

실행 또는 `Ctrl+Enter`로 시작하고, 오래 걸리는 작업은 중지 버튼으로 멈춘다.
결과 위의 `$ ctfkit ...` 줄은 같은 동작의 CLI 명령이다 (입력을 stdin으로 넘기면 `< 입력`으로 표시).

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
