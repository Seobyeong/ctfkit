# ARCHITECTURE

ctfkit 의 코드 구조와 확장 방법. 코드 리뷰를 시작할 때 이 문서부터 읽는다.

## 한눈에 보기

```
ctfkit/
├── cli.py            # 진입점. 실행할 명령의 모듈만 불러와 서브커맨드로 붙인다 (지연 로딩)
├── registry.py       # Transform 기본 클래스, @register, 자동 탐색  ← 핵심
├── analysis.py       # 통계 함수 (출력 가능 비율, 영어 빈도, 카이제곱, 일치 지수)
├── ngram.py          # 영어 바이그램 로그확률 점수 (data/english.txt 코퍼스 사용)
├── flags.py          # 플래그 형식 정규식, 탐지. 기본값은 대회 설정(settings)을 따른다
├── settings.py       # 대회 설정 .ctfkit.json 찾기·읽기·쓰기 (작업 폴더 안의 것은 무시)
├── console.py        # 입력 읽기(인자/파일/stdin), 출력(log / emit_lines), 미리보기
├── binfmt.py         # ELF / PE 파서 (rev·pwn 공용)
├── exif.py           # EXIF / TIFF 메타데이터 파서 (forensic exif)
├── rsautil.py        # RSA 정수론 도구: 분해·연분수·확장 유클리드 (rsa)
├── unpack.py         # 안전한 압축 풀기: 경로 탈출·압축 폭탄·링크 차단 (start)
├── disk.py           # 디스크 이미지: EWF(E01) 풀기, NTFS 파일·지운 파일·ADS·미할당 덩어리, 7비트 압축 글자 검색 (start·forensic disk·triage)
├── external.py       # 외부 도구 찾기·실행: 시간 제한·출력 상한, 없으면 None (triage·doctor)
├── source.py         # 소스 코드 알아보기: 언어, 단서, 분야별 명령 (triage·start)
├── recover.py        # 모양을 바꿔 숨긴 파일 되살리기: hex 글자, 바이트 더하기·XOR (forensic recover·start)
├── brief.py          # AI 에이전트용 요약: 공격 소거(ast), 값 추출, 가벼운 RSA 시도, 소스 압축 (start·triage·brief)
├── data/english.txt  # n-gram 점수용 영어 코퍼스 (패키지에 포함)
├── transforms/       # ★ 확장 지점 1: 변환 하나 = 파일 하나
│   ├── base64_.py  base58.py  base32.py  base85.py(+ascii85)  hex.py
│   ├── numeric.py(2진·8진·10진 코드, A1Z26)  morse.py  compress.py(gzip, zlib)
│   ├── url.py  textescape.py(HTML 엔티티, 이스케이프, quoted-printable)
│   ├── rot13.py  simple.py(뒤집기, ROT47, 아트배시)            (글자 암호, 키 없음)
│   └── caesar.py  railfence.py  vigenere.py  xor.py           (키 필요 + 키 추정)
├── commands/         # ★ 확장 지점 2: 명령 하나 = 파일 하나
│   ├── codec.py      # ctfkit codec list / decode / encode
│   ├── numbase.py    # ctfkit base : 진법 변환
│   ├── crack.py      # ctfkit crack <변환> : 키 추정
│   ├── auto.py       # ctfkit auto : 자동 해독
│   ├── crypto.py     # ctfkit crypto cbc-flip / pkcs7-pad / pkcs7-unpad
│   ├── rsa.py        # ctfkit rsa factor / decrypt / wiener / common-modulus
│   ├── hashes.py     # ctfkit hash id / sum / crack / hmac
│   ├── jwt.py        # ctfkit jwt decode / forge / crack
│   ├── start.py      # ctfkit start : 작업 폴더 생성·압축 풀기·전체 분석·노트 (unpack·triage·workspace 조합)
│   ├── brief.py      # ctfkit brief : 파일 하나의 제외·후보 / 줄인 소스(--code) / 값
│   ├── guide.py      # ctfkit guide : "받은 것 → 쓸 명령" 안내서 (500 토큰 이하로 유지, 테스트가 검사)
│   ├── triage.py     # ctfkit triage : 파일 분석 여러 단계를 한 번에 요약 (forensic·exif·binfmt·pwn·engine 재사용)
│   ├── forensic.py   # ctfkit forensic id / strings / carve / meta / exif / zip / pcap / lsb
│   ├── rev.py        # ctfkit rev info / disasm  (disasm 은 capstone 필요)
│   ├── pwn.py        # ctfkit pwn checksec / cyclic / rop  (rop 은 capstone 필요)
│   ├── template.py   # ctfkit template pwn / web / rsa : 풀이 스크립트 뼈대 (binfmt·pwn 의 분석 값 재사용, 실행하지 않음)
│   ├── web.py        # ctfkit web send / curl / fuzz / oracle / padding-oracle / diff  (allowlist·속도 제한)
│   ├── workspace.py  # ctfkit workspace new / list / log / info
│   ├── config.py     # ctfkit config show / set / add / remove / unset
│   ├── doctor.py     # ctfkit doctor : 외부 도구·선택 의존성 설치 상태
│   └── ui.py         # ctfkit ui : 그래픽 화면 실행
├── engine/
│   ├── search.py     # 빔 서치
│   └── scoring.py    # 후보 점수
└── gui/              # 명령을 알지 못하고 argparse 정의만 읽는다
    ├── schema.py     # argparse → 화면 구조, 입력값 → 명령줄 인자
    ├── runner.py     # 명령을 별도 프로세스로 실행하고 출력 전달
    └── app.py        # Tkinter 화면
```

의존 방향은 한쪽으로만 흐른다 (아래 → 위로 import 하지 않는다):

```
commands  →  engine  →  registry  ←  transforms
    ↘           ↘          ↑            ↙
     console     flags / analysis / ngram (공용 도구)

commands/rev, pwn → binfmt      commands/forensic → exif      commands/rsa → rsautil
```

`binfmt`·`exif`·`rsautil` 처럼 파일 형식 파싱이나 수학 계산을 하는 코드는 `commands/` 밖에 둔다.
명령 파일은 인자 처리와 출력만 맡고, 계산 모듈은 argparse 를 모르기 때문에 따로 테스트할 수 있다.

## 확장 지점 1: Transform

모든 변환은 `registry.Transform` 을 상속한다. 입력·출력은 항상 `bytes`.

| 멤버 | 용도 | 기본값 |
| --- | --- | --- |
| `name`, `aliases` | 명령어에서 쓰는 이름 | (필수), `()` |
| `description` | `codec list` 설명 | `""` |
| `decode(data, key)` / `encode(data, key)` | 변환 본체. 실패하면 `TransformError` | (필수) |
| `needs_key`, `example_key` | 키가 필요한가, 예시 키 | `False`, `None` |
| `looks_like(data)` | auto 엔진이 시도할 가치가 있는지 빠른 판별 | 항상 `True` |
| `guess_keys(data, limit)` | 키 없이 키 후보를 **빠르게** 추정. auto 가 후보마다 부르므로 가벼워야 한다 | `[]` |
| `crack_keys(data, limit)` | 키 후보를 **철저하게** 추정. `crack` 명령 전용 | `guess_keys` 와 같음 |
| `lossy` | 인코딩할 때 정보를 잃는가 (모스 부호의 대소문자 등). 왕복 테스트에서 빠진다 | `False` |
| `text_cipher` | 글자를 다른 글자로 바꾸거나 섞는 암호인가. auto 의 가지치기에 쓴다 | `False` |

새 변환을 추가하면 다음이 **코드 수정 없이** 자동으로 따라온다:
- `ctfkit codec list / decode / encode`
- `ctfkit crack` (guess_keys 를 구현한 경우)
- `ctfkit auto` 탐색 후보
- `tests/test_transforms.py` 의 왕복 테스트 (`decode(encode(x)) == x`)

```python
# ctfkit/transforms/atbash.py  (예시)
from ctfkit.registry import Transform, register

@register
class Atbash(Transform):
    name = "atbash"
    description = "알파벳 뒤집기 (a↔z)"
    def decode(self, data, key=None): ...
    def encode(self, data, key=None): ...
```

## 확장 지점 2: Command

`commands/` 의 각 모듈은 `register(subparsers)` 하나만 제공한다.
그 안에서 argparse 서브커맨드를 만들고 `set_defaults(func=실행함수)` 를 지정한다.
실행 함수는 종료 코드(int)를 반환하고, 사용자 오류는 `TransformError` 를 던지면 cli.py 가 `오류: ...` 로 출력한다.

종료 코드는 세 가지다 (`cli.py` 의 `EXIT_OK` / `EXIT_NOT_FOUND` / `EXIT_ERROR`):

| 코드 | 뜻 | 누가 정하는가 |
| --- | --- | --- |
| 0 | 찾았다 / 정상 종료 | 실행 함수가 `return 0` |
| 1 | 실행은 됐지만 찾는 것이 없다 | 실행 함수가 `return 1` |
| 2 | 입력·파일·사용법 오류 | `TransformError`·`OSError` 를 cli.py 가 2 로 바꾼다. argparse 오류도 2 |

새 명령을 만들면 `commands/guide.py` 의 안내서에도 한 줄을 넣는다. 빠뜨리면 `tests/test_guide_v024.py` 가 알려 준다.

### 지연 로딩 (v0.22)

`ctfkit hash ...` 를 실행할 때 `web` 의 urllib 이나 `ui` 의 Tkinter 까지 불러올 필요는 없다.
cli.py 는 인자에서 명령 이름을 먼저 찾고, 그 명령의 모듈 하나만 import 해 파서를 만든다.

```
argv ─→ _requested_command()  (첫 번째 옵션 아닌 인자)
     ─→ _module_for()         (commands.ALIASES → 파일 존재 확인)
     ─→ 모듈 하나만 register  ─→ 그 이름의 명령이 등록됐으면 사용
                               └ 아니면 build_parser() 로 전체를 불러온다 (-h, 잘못된 이름 등)
```

- 명령 이름이 파일 이름과 같으면 할 일이 없다. 다르면(`hash` → `hashes.py`) `commands/__init__.py` 의
  `ALIASES` 에 한 줄 적는다. 빠뜨려도 동작은 하지만 느리고, `tests/test_lazy_v022.py` 가 잡아낸다.
- 모듈 맨 위의 import 는 그 명령을 실행할 때마다 비용이 든다. 일부 하위 명령에서만 쓰는 무거운 모듈은
  함수 안에서 import 한다 (예: `pwn cyclic` 은 `binfmt` 가 필요 없다).
- 모듈 목록은 `registry.module_names()` 로 구한다. `pkgutil` 은 `inspect` 까지 불러와 30ms 가량 느리다.

## 문제 시작 (commands/start.py, unpack.py)

`start` 는 새로 분석하는 것이 없다. 이미 있는 세 가지를 조합한다.

```
문제 파일 ─→ workspace 구조 생성 ─→ files/ 에 복사
                                      │
              ┌───────────────────────┘
              ▼
        파일을 하나씩 꺼낸다 (대기열)
              │
   unpack.kind() 로 압축인지 판별 (내용 기준)
        │ 압축                     │ 아님
        ▼                          ▼
   unpack.extract()           triage.analyze()
   풀린 파일을 대기열에 추가   Report (형식, 플래그, 숨은 파일, ...)
        └──────────┬───────────────┘
                   ▼
        화면 요약 + notes.md + commands.log
```

`unpack` 은 `extractall()` 을 쓰지 않고 항목을 하나씩 검사하며 직접 쓴다. 문제 파일은 남이 만든 것이기 때문이다.

| 위험 | 막는 방법 |
| --- | --- |
| 경로 탈출 (`../../x`, `/abs/x`, `C:\x`) | `safe_target()` 이 풀 폴더 안의 경로로 바꾸고, 밖을 가리키면 거부한다 |
| 압축 폭탄 | 머리에 적힌 크기를 믿지 않고 실제로 쓴 양을 세어 상한에서 멈춘다. 쓰다 만 파일은 지운다 |
| 링크·장치 파일 (tar) | 일반 파일만 푼다 |
| 끝없는 중첩 | `--depth` 단계까지만 따라 들어간다 |

풀 수 없었던 항목은 예외로 멈추지 않고 이유와 함께 `skipped` 에 담아 돌려준다. 압축 하나가 깨져 있어도 나머지 분석은 계속된다.

디스크 이미지도 같은 대기열로 다룬다 (disk.py, 평가용 포렌식 측정 뒤). `kind()` 가 EWF 머리면 `ewf`, NTFS 부트 섹터·파티션 표·볼륨 끝의
백업 부트 섹터가 보이면 `ntfs` 를 돌려준다. E01 은 원본 디스크(`이름.raw`) 하나로 풀리고, 그 파일이 다음 단계에서 `ntfs` 로 풀린다.
NTFS 는 부트 섹터 → `$MFT` 의 runlist(조각날 수 있음) → 레코드마다 fixup 후 `$FILE_NAME`(긴 이름)·`$DATA`(본 데이터와 ADS) 를 읽고,
부모 번호로 경로를 만든다. 지운 레코드는 `_deleted/` 에, `$Bitmap` 에서 미할당인데 데이터가 있는 클러스터 덩어리는 `_unallocated/` 에 둔다.
한 바이트로만 채운 클러스터는 빈 것으로 본다. 위치 정보가 지워진 지운 파일이 모두 크기가 같은 덩어리와 하나씩만 맞을 때만 이어 붙인다.
E01 은 몇 백 KB 가 수백 MB 로 풀리므로 압축 폭탄과 같은 상한(항목·전체 크기)을 쓰고, 머리에 적힌 디스크 크기가 상한을 넘으면 풀지 않는다.

## AI 에이전트용 요약 (brief.py, v0.31)

에이전트가 소스를 받은 문제에서 토큰을 가장 많이 쓰는 곳은 틀린 공격을 시도하는 왕복이다. `brief.py` 는 공격을 추측해 제안하지 않고,
**성립하지 않는 공격을 지운다.** 지우는 근거는 코드에 사실로 보이는 것뿐이다.

```
소스 ─ ast.parse ─→ _Code (호출 목록, 이름별 대입 목록, import)
                        │
          규칙 (공격마다 전제 조건)  _rsa_rules · _cipher_rules · _random_rules · _remote_rule
                        │
          참이 확실 → 후보 / 거짓이 확실 → 제외 / 모름 → 아무것도 내지 않음
```

- **"모름" 이 기본값이다.** 이름에 값을 두 번 넣었거나 함수 인자·반복 변수면 `_Code.single()` 이 None 을 돌려주고,
  그 값에 기대는 규칙은 판정하지 않는다. 틀린 제외는 틀린 제안보다 나쁘다. 제안은 해 보고 버리면 되지만, 제외는 정답 경로를 안 보게 한다.
- **제외와 시도 실패는 다르다.** `try_rsa()` 가 페르마 2^16회에 실패했다고 페르마가 불가능한 것은 아니다. 그래서 AGENTS.md 에서도
  "제외" 와 "이미 시도함" 을 다른 절에 적는다.
- **압축은 의미를 바꾸지 않는 것만.** S-box 는 표를 소스에 다시 적지 않고 GF(2^8) 역원 + 아핀 변환으로 계산해 비교한다.
  표준과 다른 순열은 직접 만든 S-box 이고 취약점일 수 있으므로 남긴다. 줄인 자리에는 원본 줄 번호를 남겨, 에이전트가 필요하면 원본의 그 줄만 연다.
  ast 의 열 번호는 UTF-8 바이트 단위라 글자 위치로 바꿔 자른다 (`_col`).
- **소스에 적힌 값을 그대로 쓴다.** `source_constants()` 는 대입문을 줄 순서로 따라가며 상수 식(정수 사칙연산, 문자열 더하기,
  `string` 모듈 상수)만 계산한다. 상수가 아닌 값을 대입하면 그 이름은 잊는다 (`p = getPrime(); p = 123...` 이면 뒤의 값).
  큰 정수는 `try_rsa()` 의 소인수 후보가 되고(`p2 = 2*p1 + 1` 도 계산됨), 27~128글자 알파벳은 `crack_shift()` 가 쓴다.
  `try_rsa()` 는 `N1`·`FLAG1_enc` 처럼 이름의 번호로 쌍을 지어 각각 풀고, 모두 풀리면 평문을 이어 붙인다.
- **다중 시저는 소스가 알파벳을 정했을 때만.** 26글자 비즈네르는 auto 가 다루고, 소스에 62글자 같은 알파벳이 있으면 `start` 가
  일치 지수로 키 길이를, 영어 글자 빈도로 시드를, 바이그램 점수로 키를 다듬는다. 키 위치가 모든 글자마다 넘어가는 방식과
  알파벳 글자에서만 넘어가는 방식을 둘 다 본다. 플래그 형식이 나오고 평문이 엉터리가 아닐 때만 보고하며, 근거에 키와 평문 앞부분을 낸다.
- **hex 덩어리의 한 바이트 키.** `triage` 는 글자 파일 속 hex 를 바이트로 바꿔 1~255 를 빼고(바이트 시저) XOR 해 본다.
- `start` 는 이 결과를 `AGENTS.md` 에 모으고, `CLAUDE.md` 에는 `@AGENTS.md` 한 줄만 둔다 (Claude Code 는 CLAUDE.md, 다른 에이전트는 AGENTS.md 를 읽는다).
  `triage` 는 제외된 공격의 명령(cbc-flip, template remote ...)을 "다음" 에서 뺀다.

## 외부 도구 (external.py)

설치된 도구가 있으면 함께 쓰고, 없으면 내장 구현으로 대신한다. `external` 은 찾기와 실행만 하고,
어떤 파일에 어떤 도구를 돌려 출력에서 무엇을 추릴지는 `triage._check_external()` 이 정한다.

```
triage.analyze()  ─ 내장 분석 (v0.26 과 같음)
        │
        └─ _check_external()   글자 파일이 아니면
             _tools_for()      형식에 맞는 도구 고르기 (PNG·BMP → zsteg, pcap → tshark, ...)
             external.find()   없으면 report.missing 에 적고 넘어간다 → 설치 안내 한 줄
             external.run()    시간 제한·출력 상한. 실패도 예외가 아니라 Result
             _ext_<도구>()     출력에서 플래그와 눈에 띄는 줄만 추려 "도구 이름" 항목으로
```

| 위험 | 막는 방법 |
| --- | --- |
| 도구가 멈춤 | 읽기 스레드를 시간 제한만큼만 기다리고, 프로세스 트리째 끝낸다 (윈도 `taskkill /T`, 그 밖은 프로세스 그룹) |
| 출력이 끝없이 큼 | 상한까지만 읽고 프로세스를 끝낸다. 읽은 부분은 쓴다 |
| 처음 보는 출력 형식 | 도구별 추리기 함수의 예외를 삼키고 다음 도구로 넘어간다 |
| 파일 이름으로 명령 실행 | 셸을 쓰지 않고 인자 목록으로 넘긴다. 윈도의 `.bat`·`.cmd` 도구에는 cmd.exe 특수 문자가 든 인자를 넘기지 않는다 |
| 환경마다 다른 결과 | `CTFKIT_NO_EXTERNAL=1` 이면 쓰지 않는다. 테스트(conftest)와 토큰 벤치마크는 이 값으로 돌린다 |

테스트는 진짜 도구 대신 파이썬으로 만든 가짜 실행 파일만 있는 PATH 로 돌린다 (`tests/test_external_v027.py`).

## 대회 설정 (settings.py)

플래그 형식을 쓰는 곳은 많지만(엔진, 변환의 키 추정, triage, 그래픽 화면 ...) 모두 `flags.compile_flag_pattern()` 을 거친다.
그래서 설정을 읽는 곳은 `flags.default_pattern()` 한 곳이고, 명령마다 설정 코드를 넣지 않았다.
모듈을 불러올 때 정규식을 미리 만들어 두던 곳(caesar, simple)은 쓸 때 만들도록 바꿨다. 설정은 import 뒤에 정해질 수 있다.

```
--flag 있음 ─────────────────────────→ 그 정규식
--flag 없음 → settings.current().flag → 대회 설정
                   └ 없음 ───────────→ DEFAULT_FLAG_PATTERN (v0.28 과 같음)
```

`settings.find()` 는 현재 폴더(또는 `set_base()` 로 준 폴더)에서 위로 올라가며 `.ctfkit.json` 을 찾되, 가장 가까운 작업 폴더
(`.ctfkit-workspace` 표시가 있는 폴더) 안에 있는 것은 건너뛴다. 작업 폴더에는 남이 만든 문제 파일이 풀려 있기 때문이다.

## 그래픽 화면 (gui/)

화면 항목을 따로 적지 않고 `build_parser()` 가 만든 argparse 정의를 읽어 생성한다. 실행은 `python -m ctfkit <인자>` 를 별도 프로세스로 띄우는 방식이라, CLI 와 화면의 동작이 항상 같다.

```
commands/*.py 의 argparse ─→ schema.build_schema() ─→ app (입력 항목 표시)
                                                       │ 입력값
              runner.Job (별도 프로세스) ←─ schema.build_argv()
```

기능을 추가할 때 화면 쪽에서 할 일:

| 추가하는 것 | 화면에서 일어나는 일 | 추가 작업 |
| --- | --- | --- |
| 새 변환 (`transforms/`) | `codec`·`crack` 목록에 자동 추가 | 없음 |
| 새 옵션 (`add_argument`) | 입력 항목 자동 추가 | 없음 |
| 새 명령 (`commands/`) | 사이드바에 자동 추가, 라벨은 help 문구 사용 | 없음 |
| 라벨·순서·묶음·입력 방식 다듬기 | | 명령 파일에 `GUI_HINTS` (선택, 형식은 `gui/schema.py` 참고) |
| "예시 채우기" 값 | 실행 버튼 옆에 링크가 생긴다 | `GUI_HINTS` 의 `examples` (선택). 테스트가 예시를 실제로 실행해 본다 |

입력 방식은 argparse 정의로 정해진다: `store_true` → 체크박스, `choices` → 목록, `type=int/float` → 숫자 칸, 위치 인자 기본값 `-` → 여러 줄 입력(stdin), `append`·`nargs='+'` → 한 줄에 값 하나. 옵션 이름이 `file`·`words`·`cookies`·`dump`·`root` 면 파일·폴더 선택 버튼이 붙는다.

화면 배치도 argparse 정의에서 정해진다 (`gui/app.py`):

- **사이드바 묶음:** `GUI_HINTS` 의 `group` 이 같은 명령끼리 한 머리글 아래에 모인다. 지정하지 않으면 "기타".
- **옵션 접기:** 필수가 아닌 옵션이 3개를 넘으면 "옵션 더 보기" 로 접는다(`split_fields`). 입력 파일(`file`)은
  입력 칸의 대안이라 항상 보인다. 접힌 옵션에 값을 바꿔 두었으면 자동으로 펼친다.
- **플래그 줄:** 출력에서 플래그 정규식에 맞는 글자를 찾으면 결과 위에 따로 보여 준다.
- **설명 풍선:** argparse 의 `help` 전체를 `Field.help` 로 싣고, 항목 이름에 마우스를 올리면 보여 준다.
  라벨은 짧게 두고 기본값·형식 예시는 `help` 에 적으면 된다.
- **입력 문제 위치:** `build_argv` 가 던지는 `InputProblem` 에 문제가 된 항목 이름(`dest`)이 들어 있어,
  화면이 그 입력 칸을 강조하고 커서를 옮긴다. 접힌 옵션 안의 문제면 펼친다.
- **화면별 결과:** 결과는 `(명령, 하위 명령)` 마다 `Output` 객체에 따로 쌓는다. 실행 중인 작업의 출력은
  시작한 화면의 `Output` 에 들어가고, 그 화면을 보고 있을 때만 위젯에 그린다. 화면을 옮기면 그 화면의
  `Output` 을 다시 그린다.
- **다른 도구로 보내기:** 글자 입력(stdin) 항목이 있는 화면을 schema 에서 찾아 메뉴로 만든다. 새 명령이
  글자 입력을 받으면 메뉴에도 자동으로 나타난다.

`tests/test_gui_schema.py` 는 모든 명령을 순회하며 생성한 인자가 실제 argparse 를 통과하는지 검사하므로, 새 명령도 테스트를 추가하지 않아도 이 검사를 받는다.

입력과 결과가 "실행 → 텍스트 출력" 형태를 벗어나는 기능(대화형 입력, 그래프 등)은 자동 생성 범위 밖이라 `app.py` 에 전용 화면을 추가해야 한다.

## auto 엔진 (engine/search.py)

빔 서치. 매 단계마다:

1. 현재 후보마다 `looks_like` 를 통과한 모든 변환을 적용한다. 키가 필요한 변환은 `guess_keys` 결과로 시도한다. 키 없는 변환이 먼저 (같은 결과면 `rot13` 이 `caesar(13)` 보다 먼저 기록되도록).
2. 이미 본 결과(`seen`)는 버린다. 순환과 중복 방지.
3. 플래그 정규식에 맞는 결과가 나오면 그 단계에서 멈춘다 (가장 짧은 경로).
4. 아니면 점수 상위 `beam` 개만 다음 단계로 넘긴다. 이미 영어로 읽히는 후보(`SOLVED_THRESHOLD`)는 더 풀지 않는다.

최종 순위는 `rank_score = score − 0.02×단계 수 − 0.05×키 추정 단계 수`.
키를 추정한 단계는 데이터에 맞춰 고른 것이라 점수가 부풀려지는 경향(과적합)이 있어서 더 깎는다.

### 시도하지 않는 조합 (가지치기)

변환이 늘면 조합이 늘고, 조합이 늘면 우연히 플래그 모양이 된 쓰레기(오탐)도 늘어난다.
`_worth_trying` 이 의미 없는 조합을 미리 잘라 낸다. 모두 실제로 가짜 플래그가 나온 사례에서 만든 규칙이다.

| 규칙 | 이유 |
| --- | --- |
| 글자 입력에 곧바로 XOR 하지 않는다 | XOR 암호문은 hex·base64 로 적혀 오거나 파일로 온다. 글자열에 플래그 접두사를 가정한 키를 대면 가짜 플래그가 나온다 |
| 글자 암호를 푼 결과에 XOR 하지 않는다 | 같은 이유 |
| 키가 필요한 같은 암호를 연달아 두 번 풀지 않는다 | 시저 두 번은 시저 한 번과 같고, 레일 펜스 두 번은 글자를 아무렇게나 섞는 것과 같다 |
| 글자 암호는 한 경로에서 두 번까지 | 글자 암호는 어떤 글자열에든 적용되므로 여러 번 겹치면 무엇이든 만들 수 있다 |

변환 쪽에서도 `looks_like` 를 좁게 잡는다. 시저·비즈네르·아트배시는 알파벳이 절반 이상일 때만, 뒤집기는
닫는 괄호가 앞에 있거나 뒤집어야 다른 변환이 풀릴 때만, base85 는 디코드 결과가 전부 글자일 때만 시도한다.

플래그 후보가 여럿이면 괄호 안이 영숫자·밑줄 위주인 것을 앞에 둔다(`flags.flag_quality`).
입력에 이미 플래그가 있으면 변환하지 않고 그대로 돌려준다.

이 규칙들이 실제로 오탐을 막는지는 `bench/solve.py` 의 "플래그가 없는 입력" 72개로 잰다.

### 점수 (analysis.py)

- `printable_ratio`: 출력 가능한 ASCII 비율
- `english_score`: (알파벳 + 흔한 문장부호 비율) × 1/(1 + χ²/n)
- `text_score`: 바이너리면 낮게, 텍스트면 printable 과 english 의 평균
- 플래그가 있으면 1.0

## 키 추정 (crack)

| 변환 | 방법 |
| --- | --- |
| caesar | 26개 이동을 모두 시도해 카이제곱(영어 빈도와의 거리)이 작은 순 |
| vigenere | ① 일치 지수(IC)로 키 길이 후보 → ② 열마다 시저처럼 카이제곱으로 이동 칸 수(시드 키) → ③ 영어 바이그램 점수(`ngram.py`)로 언덕 오르기를 해 키를 다듬기 → ④ `KEYKEY` 같은 반복 키를 `KEY` 로 축약 |
| xor | ① 알려진 평문 공격: 플래그 접두사(`DH{` 등)로 시작한다고 가정해 키 계산, 여러 바이트 키 가능 → ② 1바이트 키 256개 전수 조사 후 text_score 순 → ③ 해밍 거리로 키 길이를 추정하고 열마다 1바이트 XOR 로 풀어 다중 바이트 키 복구 |

RSA(`rsa` 명령, `rsautil.py`)는 키 추정이 아니라 약한 설정을 노린 계산이다: 페르마·폴라드 로·시험 나눗셈으로 분해, 연분수로 비너 공격, 확장 유클리드로 공통 모듈러스 공격.

## 참고한 기존 도구

- CyberChef의 "Magic" 연산: 여러 겹 인코딩을 자동 탐지하는 아이디어
- Ciphey: 점수 기반으로 암호·인코딩을 자동 해독하는 아이디어

위 도구들의 코드는 사용하지 않았다. ctfkit의 코드는 대부분 AI(Claude Code)가 작성하고 사람이 리뷰했다(README의 "AI 활용" 참고). 고전 암호 분석 기법(빈도 분석, 일치 지수, 알려진 평문 공격)은 교과서적인 방법이다.
