# 개발 일지 (devlog)

매 작업 후 3줄만 남긴다: **오늘 한 것 / 막힌 것 / 배운 것**.
발표 자료와 커밋 메시지의 재료가 된다.

---

## 2026-09-18 — 프로젝트 시작

- 한 것: 저장소 뼈대 생성 (README, ROADMAP, .gitignore). 주제를 드림핵 워게임 보조 CLI로 확정.
- 막힌 것: (아직 없음)
- 배운 것: 오픈소스 프로젝트는 코드보다 먼저 "무엇을·왜·어디까지" 문서로 정하고 시작한다.

<!--
다음 일지 템플릿:

## YYYY-MM-DD — 제목

- 한 것:
- 막힌 것:
- 배운 것:
-->


## 2026/10/01 - base64 decoding
- 한 것 : 디코딩 기능 추가를 위한 codec.py 파일 작성
- 막힌 것 : codec.py를 작성하는 과정에서 b64decode를 통해서 인코딩된 data를 result에 디코딩해서 넣었지만 결과값을 출력할 경우 앞에 b가 붙는 경우가 발생.
    - 이를 해결하기 위해서 result뒤에 .decode()를 붙여서 해결
    - 문제 원인은 b64decode의 반환값이 byte형식이기에 그런 것.
    - decode는 byte형식을 str형식으로 바꿔주기에 문제가 해결되었음
- 배운 것 : b64decode()는 byte 형식을 반환하고 decode()는 byte를 str형식으로 반환함

## 2026/10/07 - hex decoding
- 한 것 : hex 디코딩 추가를 위한 codec.py 수정
- 막힌 것 : base64 decoding과 크게 다르지 않았기에 막힌 부분 없음
- 배운 것 : -

## 2026/10/28 - 방향 재설정 + codec·auto·crack 재구성 (v0.1 ~ v0.4)
- 한 것 : ROADMAP을 올인원 CTF 도구 방향으로 재설정. Claude Code가 작성한 코드를 리뷰하는 방식으로 진행.
    - 플러그인 레지스트리 구조로 재구성, codec 변환 6종(base64, base32, hex, URL, ROT13, XOR)
    - auto: 빔 서치 + 점수 함수로 여러 겹 인코딩을 자동 복원
    - crack: 시저 / 비즈네르(일치 지수로 키 길이 추정) / XOR 키 추정
    - GitHub Actions CI(테스트·커버리지) 추가
- 막힌 것 : Windows CI 스모크 테스트에서 한글 출력이 cp1252 콘솔로 파이프될 때 UnicodeEncodeError로 종료됨
    - 표현할 수 없는 문자는 '?'로 바꿔 출력하도록 수정
- 배운 것 : 콘솔 출력 인코딩은 OS·로케일마다 다르므로, 내 PC에서 되는 것과 CI에서 되는 것은 별개다.

## 2026/10/29 - web·forensic·hash·workspace 모듈 추가 (v0.5 ~ v0.7)
- 한 것 : 나머지 핵심 모듈 4개를 추가하고 리뷰함. 테스트 163개 통과, 커버리지 91%.
    - web: send / curl 명령 재현 / fuzz. allowlist(localhost·워게임 인스턴스)와 속도 제한·총량 상한을 둬서 학습 범위 밖으로는 요청이 안 나가게 함.
    - forensic: 매직 바이트로 형식 판별, 문자열·플래그 추출, 뒤에 붙인 숨은 파일(트레일러) 탐지·추출, LSB 추출(Pillow 선택 의존성).
    - hash: 길이·문자셋 휴리스틱으로 종류 판별, 워드리스트 사전 공격, 해시 계산, HMAC.
    - workspace: 문제별 폴더 생성, 실행 명령 기록, 풀이 노트(Markdown) 템플릿.
    - 버전 0.1.0 → 0.7.0, pyproject에 image 선택 의존성, CI에 hash 스모크 테스트 추가.
- 막힌 것 : 모듈이 한 번에 4개라 커밋을 어떻게 나눌지 고민. 모듈+테스트 단위로 쪼개서 커밋하기로 함(web, hash, forensic, workspace, 마지막에 문서·버전).
- 배운 것 : cli.py가 commands 폴더를 자동 로드해서 모듈 추가에 등록 코드가 필요 없음 — 플러그인 구조 덕에 "파일 하나 = 명령 하나"가 실제로 지켜짐.
- 다음 : 분야별 드림핵 문제를 ctfkit만으로 풀어 보며 임계값·사용성을 조율(v0.6 통과 조건). 실제 풀이에서 나온 문제를 다시 리뷰로.

## 2026/11/06 - 그래픽 화면 추가 (v0.8)
- 한 것 : Tkinter 시안을 확인한 뒤 `ctfkit ui` 로 구현함. 표준 라이브러리만 사용.
    - 항목을 직접 적지 않고 argparse 정의에서 화면을 자동 생성해, 기능을 추가해도 화면 코드를 고치지 않아도 되게 함. 다듬을 부분만 명령 파일의 `GUI_HINTS` 로 지정.
    - 명령은 별도 프로세스로 실행해 화면 멈춤을 막고 중지 기능을 넣음.
    - `web fuzz --hide abc`, `web curl "curl -X"` 가 Traceback 을 내던 문제를 짧은 오류 메시지로 수정.
    - 시안 샘플에서 `forensic meta` 가 `flag.txtDH{...}` 의 플래그를 놓치는 것을 발견. `forensic` 에서만 단어 경계 없는 패턴을 쓰도록 수정 (다른 명령은 오탐 방지를 위해 유지).
- 막힌 것 : stdout·stderr를 따로 읽었더니 출력 순서가 뒤바뀜(`HTTP 200` 이 본문 뒤에 나옴). 한 파이프로 합쳐서 해결.
- 다음 : 힌트 없는 새 명령이 화면에서 어떻게 보이는지 실제 추가 기능으로 확인.

## 2026/11/09 - web oracle 추가 + fuzz 본문 필터 (v0.9)
- 한 것 : `web oracle` 서브커맨드와 `web fuzz --match/--fail` 본문 필터를 추가하고 리뷰함. 테스트 248개 통과.
    - `web oracle`: `secret[0:len(guess)] == guess` 처럼 입력 길이만큼만 비교하는 취약점을, `FUZZ` 자리에
      (복구한 접두사 + charset 글자)를 붙여 가며 한 글자씩 자동 복구한다. `--success`/`--fail` 정규식으로
      "맞은 접두사"를 판별하고, 틀리면 다음 글자, 더 늘릴 수 없으면 종료.
    - `web fuzz`: 상태코드(`--hide`)만이 아니라 응답 **본문**을 정규식으로 거를 수 있게 `--match`/`--fail` 추가.
      정답 응답(예: `FLAG`)만 남겨 눈으로 크기를 비교하지 않아도 되게 함.
- 왜 추가했나(기능 추가 이유) :
    - 실제 드림핵 locker 유형 문제(사물함 번호 4자리 `[a-z0-9]` + 비밀번호 100~200)를 ctfkit 만으로 풀어 보니,
      기존 `web fuzz` 로는 (1) `FUZZ` 마커가 한 개뿐이라 두 값을 한 번에 못 돌리고, (2) 이전 결과를 다음
      입력에 이어 붙이는 **적응형 탐색**이 없어 접두사 오라클을 자동화할 수 없었다. (3) 정답 판정도 응답
      크기를 눈으로 비교해야 했다.
    - 이 문제의 핵심 취약점은 `rand_str[0:len(locker_num)] == locker_num` — 입력한 길이만큼만 비교하는
      접두사 오라클이다. 전수 대입이면 36⁴≈168만 가지지만, 한 글자씩 확정하면 **36×4=144번**이면 된다.
      이 "한 글자씩 확정" 패턴은 locker 한 문제만이 아니라 길이 의존 비교·타이밍 오라클 등에서 반복되므로,
      일회성 스크립트 대신 재사용 가능한 명령으로 만드는 게 맞다고 판단해 `web oracle` 로 일반화했다.
    - 비밀번호 단계(전체 번호 확정 후 100~200 스윕)는 접두사 탐색이 아니라 단순 반복이라 `web fuzz` 가 맞는데,
      정답만 골라내려면 본문 필터가 필요해 `--match`/`--fail` 을 같이 넣었다. 결과적으로 이 유형을
      `oracle`(번호) + `fuzz --match`(비번) 두 명령으로 풀 수 있게 됐다.
    - allowlist·`--delay`·`--max` 안전장치는 그대로 유지(`oracle` 도 총량 상한 기본 2000)해서 학습 범위를 벗어난
      대량 요청이 나가지 않게 했다.
- 막힌 것 : `oracle` 의 진행 로그(`[1] k`)를 stdout 에 찍었더니, 복구값을 파이프로 넘길 때 중간 로그가 섞였다.
    진행·요약은 stderr, 최종 복구값만 stdout 으로 분리해 `ctfkit web oracle ... > out` 이 깔끔하게 값만 담도록 함.
- 배운 것 : 퍼징과 오라클은 겉보기엔 비슷해도 **"각 시도가 독립인가, 이전 결과에 의존하는가"** 가 다르다.
    독립이면 워드리스트 반복(fuzz), 의존이면 상태를 들고 가는 적응형 탐색(oracle)으로 나누는 게 자연스럽다.

## 2026/11/09 - 패딩 오라클 + crypto 모듈 (v0.10)
- 한 것 : `web padding-oracle` 와 새 `crypto` 명령(cbc-flip, pkcs7-pad, pkcs7-unpad)을 추가하고 리뷰함.
  테스트 268개 통과. **외부 의존성 없이 표준 라이브러리만** 사용.
    - `web padding-oracle`: CBC/PKCS7 패딩 오라클로 키 없이 암호문을 복호화. 타깃 블록 앞에 조작 블록 X 를
      붙인 `[X][C_t]` 를 보내 패딩이 맞는 X 를 찾고, 중간값 D(C_t) 를 한 바이트씩 복원 → 평문 = D(C_t) XOR 이전블록.
      `--bad`/`--ok` 정규식으로 서버의 패딩 오류 응답을 판별, `--iv` 로 첫 블록까지 복원.
    - `crypto cbc-flip`: 이전 블록(또는 IV) 바이트를 XOR 조작해 다음 블록 평문을 원하는 값으로 바꾸는 비트플립.
    - `crypto pkcs7-pad`/`pkcs7-unpad`: PKCS7 패딩 유틸.
- 왜 추가했나(기능 추가 이유) :
    - 드림핵 AES 유형(로그인→토큰 발급, `/secure/decrypt` 로 암호문 복호화) 문제를 ctfkit 으로 풀어 보니,
      기존 모듈로는 **블록 암호 공격 자체가 불가능**했다. `codec`(base64)·`web send` 로 재료 준비까지는 되는데,
      핵심인 "키 없이 암호문을 복원"하는 단계가 비어 있었다.
    - 소스를 보니 `AESCrypto` 가 **CBC + 고정 IV(0) + PKCS7** 이고, `/secure/decrypt` 가 패딩 오류(`ValueError`)를
      다른 오류와 **구분되는 메시지로 응답**했다 — 교과서적인 패딩 오라클. 권한 체크를 우회할 필요도 없이,
      admin 글의 `enc_data` 를 오라클로 그대로 복호화하면 `The password is: ...` 가 평문으로 샜다.
    - 지난번 `web oracle`(접두사 오라클)과는 **메커니즘이 완전히 다르다**(바이트 조작 + 중간값 XOR, blockwise).
      그래서 별도 명령으로 분리했다. 패딩 오라클·비트플립·PKCS7 은 CBC CTF 단골이라 일회성 스크립트보다
      재사용 가능한 명령이 맞다고 판단.
    - 기능 범위는 **외부 의존성 유무**로 그었다. 패딩 오라클·비트플립·패딩 유틸은 전부 바이트 XOR 라 표준
      라이브러리로 되지만, 키/IV 를 알 때의 AES 직접 암복호화는 암호 라이브러리가 필요해 이번엔 뺐다
      (`[image]` 처럼 선택 의존성으로 나중에).
- 막힌 것 : 패딩 오라클 통합 테스트가 AES 라이브러리 없이도 되게 만들어야 했다. 공격이 **CBC 구조 + PKCS7**
    에만 의존한다는 점을 이용해, `D(block)=block^KEY` 인 가역 토이 블록 암호로 서버를 재현했다(의존성 0).
    또 테스트가 수천 요청이라 느려서(블록 16 기준 ~33초) **블록 8 짜리 토이 암호**로 줄여 ~16초로 맞췄다.
- 배운 것 : 패딩 오라클은 "암호를 깬다"기보다 **"서버가 패딩 성공/실패를 알려준다"는 정보 한 비트**를
    모아 복원하는 공격이다. 그래서 공격·테스트 모두 AES 그 자체가 아니라 CBC+PKCS7 구조에만 의존한다.

## 2026/11/10 - jwt 모듈 (v0.11, Phase 1 시작)
- 한 것 : 로드맵을 "드림핵 전 분야 기본기 먼저(넓이) → 그다음 심화(깊이)"로 새로 쓰고, 그 Phase 1
  첫 단계로 `jwt` 명령(decode / forge / crack)을 추가·리뷰함. 테스트 19개 추가(총 287개 통과).
  **외부 의존성 없이 표준 라이브러리만**(base64, json, hmac, hashlib) 사용.
    - `jwt decode`: 헤더·페이로드를 base64url 디코드해 JSON 으로 출력. `--verify SECRET` 로 HS 서명 검증.
      alg=none 이면 경고를 띄운다(서명 미검증 서버면 변조 가능).
    - `jwt forge`: 기준 토큰을 받아(없으면 빈 페이로드) `--set KEY=VALUE` 로 클레임 수정, `--alg` 로 알고리즘
      교체. `--alg none` 이면 서명 조각을 비우고, HS256/384/512 면 `--secret` 으로 재서명.
    - `jwt crack`: HS 계열 토큰의 서명을 워드리스트로 재현해 시크릿을 찾는다.
- 왜 추가했나(분야·우선순위) :
    - 드림핵 웹/암호에서 JWT 는 입문 단골이고(`alg:none` 우회, 약한 시크릿), 기존 모듈로는 손댈 수 없었다.
      Phase 1 목표가 "모든 분야 기본기"라 넓이 관점에서 가장 저렴하게(표준 라이브러리만) 한 분야를 여는 선택.
    - 범위를 **대칭키(HS)** 로 그었다. RS/ES(비대칭)는 개인키가 있어야 서명·크랙이 되고 입문 범위 밖이라 뺐다.
      decode 는 알고리즘 무관하게 되지만, forge 재서명·crack 은 HS 로 한정.
- 설계 판단 :
    - `--set` 값은 `json.loads` 로 먼저 해석(`true`→불리언, `7`→정수)하고 실패하면 문자열. CTF 에서 `admin=true`
      처럼 타입이 중요한 변조가 많아서다.
    - 진행 로그/경고(alg, 검증 결과)는 stderr, 최종 토큰만 stdout 으로 분리 — `forge` 출력이 그대로
      다음 명령으로 파이프되게(기존 `web oracle` 과 같은 규칙).
    - base64url 패딩('=')은 JWT 규격상 떼어내므로, 디코드 때 길이에 맞춰 다시 채워 준다.
- 막힌 것 : GUI 스키마 테스트(`test_every_command_appears_once...`)가 명령 목록을 하드코딩하고 있어,
    `jwt` 추가로 깨졌다. 사이드바 순서(order=65, web 과 workspace 사이)에 맞춰 기대값에 `jwt` 를 끼워 수정.
- 배운 것 : JWT 공격은 암호를 깨는 게 아니라 **서버가 서명을 제대로 검증하느냐**를 노린다. `alg:none` 은
    "서명 없음"을 서버가 허용하면 끝이고, HS256 크랙은 시크릿이 약할 때만 통한다 — 둘 다 암호 자체가 아니라
    구현/설정의 허점이다. 그래서 공격 도구도 표준 라이브러리 수준이면 충분하다.

### 리뷰 반영 (확장성)
- `0x`-16진수 키 파싱이 `hash` 와 `jwt` 에 복붙돼 있던 걸 `console.parse_key()` 로 합쳤다
  (앞으로 키를 받는 crypto 계열 명령이 늘어도 한 군데만 보면 된다).
- `jwt decode`/`crack` 이 토큰을 인자로만 받던 걸, 다른 명령처럼 stdin(`-`)도 받게 통일했다
  (`cat token | ctfkit jwt decode`). base64url 헬퍼는 아직 jwt 만 써서 공용화는 미룸(YAGNI).

## 2026/11/10 - rev 모듈 (v0.12, Phase 1 리버싱)
- 한 것 : 실행 파일 정적 분석 `rev` 명령(info / disasm)과, 그 기반이 되는 바이너리 파서
  `ctfkit/binfmt.py` 를 추가·리뷰함. 테스트 14개 추가(총 303개 통과).
    - `binfmt.parse`: **표준 라이브러리(struct)만으로** ELF32/64(LE/BE)·PE32/PE32+ 를 파싱.
      아키텍처·엔디언·타입·entry·섹션(이름/주소/오프셋/크기)·심볼(FUNC/OBJECT)을 뽑고,
      `section_at(vaddr)` 로 가상주소 → 파일 오프셋 변환까지 제공.
    - `rev info`: 위 요약 출력(`--sections` 로 섹션 목록도).
    - `rev disasm`: capstone(선택 의존성)으로 entry/주소/오프셋부터 N개 명령 디스어셈블.
- 왜 이렇게 나눴나(설계) :
    - **파싱과 디스어셈블을 분리**했다. 바이너리 헤더 파싱은 표준 라이브러리로 충분하고(의존성 0),
      무거운 건 디스어셈블뿐이라 capstone 을 `forensic lsb` 의 Pillow 처럼 **선택 의존성(`[rev]`)** 으로
      뺐다. capstone 없이도 `rev info` 는 그대로 동작한다.
    - binfmt 를 명령이 아니라 **별도 모듈**로 둔 이유: 이후 `pwn checksec`(NX/PIE/RELRO 판정)도
      같은 ELF/PE 파싱이 필요하다. 명령(commands/)은 자동 등록 대상이라, 공용 파서는 commands/ 밖에 둬서
      재사용하게 했다.
    - 아키텍처를 capstone 상수에 바로 묶지 않고 `arch` 키("x64" 등) 로만 들고, rev 에서 실행 시점에
      capstone 상수로 매핑했다. binfmt 가 capstone 유무와 무관하게 import 되도록.
- 막힌 것 : 실제 ELF 없이 테스트하기. 최소 ELF64(.text=nop;nop;ret + main 심볼)와 PE32+ 를
    바이트로 직접 만들어(struct) 파서를 검증했다. disasm 은 capstone 이 없을 수 있어
    `importorskip` 으로 건너뛰고, "capstone 없음" 안내 경로는 import 를 가로채 따로 검증했다.
    실제 바이너리로도 확인: 이 PC 의 python.exe 를 `rev info`(PE 64-bit x86-64)·`rev disasm`
    (entry 의 `sub rsp,0x28; call ...`)로 제대로 읽었다.
- 배운 것 : ELF/PE 는 결국 "헤더에서 테이블 위치를 읽고, 그 테이블로 또 다른 테이블을 읽는" 구조다.
    섹션 이름조차 별도 문자열 테이블(.shstrtab)에 있고 심볼 이름은 또 다른(.strtab) 테이블에 있다.
    가상주소를 파일 오프셋으로 바꾸는 계산(섹션의 addr/offset 차)이 disasm 과 (앞으로) 가젯 탐색의 핵심.

## 2026/11/10 - pwn 모듈 (v0.13, Phase 1 포너블)
- 한 것 : `pwn` 명령(checksec / cyclic / rop)과, 이를 위해 `binfmt` 에 프로그램 헤더(세그먼트)·
  .dynamic·PE DllCharacteristics 파싱을 추가함. 테스트 13개 추가(총 322개 통과).
    - `pwn checksec`: NX(GNU_STACK 실행권한)·PIE(e_type DYN)·Canary(__stack_chk_fail 심볼)·
      RELRO(GNU_RELRO + BIND_NOW) 를 판정. PE 는 DllCharacteristics 로 DEP/ASLR/CFG 표시.
    - `pwn cyclic`: de Bruijn 수열로 패턴 생성, `--lookup` 으로 오프셋 역산('faaa' 또는 0x.. 리틀엔디언).
    - `pwn rop`: 실행 영역에서 ret(0xc3) 앞 바이트를 디스어셈블해 유효 가젯 수집, `-f` 로 필터(capstone).
- 왜 binfmt 를 키웠나(설계) :
    - checksec 은 결국 **헤더를 읽어 판정하는 일**이라, v0.12 에서 만든 `binfmt` 에 세그먼트·dynamic
      파싱만 더하면 됐다. rev(info/disasm) 와 pwn(checksec/rop) 이 같은 파서를 공유하게 돼,
      "파싱은 한 곳, 해석은 각 명령" 구조가 그대로 유지됐다.
    - PE 의 Subsystem·DllCharacteristics 가 PE32/PE32+ 모두 옵션 헤더 오프셋 68/70 에 있다는 점을
      이용(앞쪽 ImageBase 크기 차이가 뒤에서 상쇄)해, 분기 없이 한 줄로 읽었다.
    - cyclic 은 의존성이 필요 없고(순수 알고리즘), rop 만 capstone 이 필요하다. 그래서 checksec·cyclic 은
      기본, rop 은 `[rev]` extras 로 두되 같은 명령 아래 묶었다(세 가지 다 "포너블 준비 작업"이라).
- 막힌 것 : 보호 기법 조합별 ELF 를 실제로 구할 수 없어서, 테스트에서 프로그램 헤더+dynamic+심볼을
    가진 ELF 를 조합(pie/nx/canary/relro)별로 직접 만들었다. 처음에 프로그램 헤더를 56바이트가 아니라
    48바이트로(=p_align 8바이트 누락) 조립해 전체 크기가 어긋났는데, 크기 단언으로 바로 잡았다.
    실제 python.exe 로도 checksec 확인(DEP/ASLR 켜짐).
- 배운 것 : checksec 가 보는 건 암호가 아니라 **링커가 남긴 흔적**이다. NX 는 GNU_STACK 세그먼트의
    실행 비트, PIE 는 파일 타입(DYN), Canary 는 __stack_chk_fail 심볼의 유무, RELRO 는 GNU_RELRO
    세그먼트와 BIND_NOW 태그 — 전부 헤더/테이블을 읽으면 나온다. ROP 가젯도 "ret 로 끝나는, 빈틈없이
    디코드되는 짧은 바이트열"을 모으는 것이라 디스어셈블러만 있으면 된다.

## 2026/11/10 - forensic 확장 (v0.14, Phase 1 포렌식 보강)
- 한 것 : `forensic` 에 exif/zip/pcap 하위 명령과 lsb 채널 선택(-c)을 추가하고, EXIF 파서를
  별도 모듈 `ctfkit/exif.py` 로 만들었다. 테스트 15개 추가(총 337개 통과). **전부 표준 라이브러리.**
    - `forensic exif`: JPEG APP1("Exif\0\0") 또는 TIFF 를 직접 파싱 — 바이트 순서 → IFD0 →
      Exif/GPS 서브 IFD 를 따라가며 Make/Model/DateTime/Artist/UserComment/GPS 등 태그를 덤프.
    - `forensic zip`: `zipfile` 로 항목 목록(이름·크기·압축·암호 여부). 뒤에 붙여 둔 ZIP 도 읽힌다.
    - `forensic pcap`: classic pcap 의 레코드를 직접 훑어 페이로드의 문자열을 추출(pcapng 미지원).
    - `forensic lsb -c`: R/G/B 중 쓸 채널과 순서를 고를 수 있게 함(예: `-c r`).
- 왜 이렇게 했나(설계) :
    - EXIF 파서를 **Pillow 가 아니라 직접** 구현한 이유: 메타데이터 열람은 포렌식 기본기라 선택
      의존성 뒤에 숨기고 싶지 않았고, TIFF/IFD 는 포맷이 명확해 표준 라이브러리로 충분하다(학습 가치도 큼).
      LSB 만 Pillow 가 필요한데, 이건 픽셀 디코딩이 필요해서다.
    - EXIF 를 `exif.py` 별도 모듈로 뺀 건 binfmt 와 같은 이유 — 파싱 로직은 명령(commands/) 밖에 두고
      재사용·테스트 가능하게. 출력(사람이 보는 표)은 명령이 담당.
    - pcap 은 일단 classic 만. pcapng 는 블록 구조가 달라 범위를 넘고, 드림핵 입문은 대개 classic 이다.
- 막힌 것 : 테스트용 이미지/캡처를 구할 수 없어 전부 바이트로 합성했다. 최소 TIFF(IFD0 3개 태그)와
    그걸 감싼 JPEG APP1, 그리고 리틀엔디언 classic pcap(패킷 2개)을 struct 로 만들어 검증.
    pcap 전역 헤더를 `<I` 로 쓰면 매직이 파일에 d4c3b2a1 로 저장돼(= 리틀엔디언 파일) 파서가 올바르게
    엔디언을 잡는 것도 확인.
- 배운 것 : EXIF 는 사실상 파일 안에 든 작은 TIFF다. "값이 4바이트 이하면 엔트리 안에 그대로, 넘으면
    오프셋"이라는 규칙과, ExifIFD/GPSIFD 가 태그가 가리키는 별도 IFD 라는 구조만 알면 따라갈 수 있다.
    포렌식의 많은 부분이 "컨테이너 안의 컨테이너"(JPEG>APP1>TIFF>IFD, PNG 뒤 ZIP, pcap>패킷)를
    한 겹씩 벗기는 일이라는 게 이번에 분명해졌다.
