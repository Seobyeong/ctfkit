# ARCHITECTURE

ctfkit 의 코드 구조와 확장 방법. 코드 리뷰를 시작할 때 이 문서부터 읽는다.

## 한눈에 보기

```
ctfkit/
├── cli.py            # 진입점. commands/ 의 모듈을 자동으로 서브커맨드로 붙인다
├── registry.py       # Transform 기본 클래스, @register, 자동 탐색  ← 핵심
├── analysis.py       # 통계 함수 (출력 가능 비율, 영어 빈도, 카이제곱, 일치 지수)
├── flags.py          # 플래그 형식 정규식, 탐지
├── console.py        # 입력 읽기(인자/파일/stdin), 출력, 미리보기
├── transforms/       # ★ 확장 지점 1: 변환 하나 = 파일 하나
│   ├── base64_.py  base32.py  hex.py  url.py  rot13.py      (키 없음)
│   └── caesar.py   vigenere.py  xor.py                      (키 필요 + 키 추정)
├── commands/         # ★ 확장 지점 2: 명령 하나 = 파일 하나
│   ├── codec.py      # ctfkit codec list / decode / encode
│   ├── crack.py      # ctfkit crack <변환> : 키 추정
│   ├── auto.py       # ctfkit auto : 자동 해독
│   ├── hashes.py     # ctfkit hash id / sum / crack / hmac
│   ├── forensic.py   # ctfkit forensic id / strings / carve / meta / lsb
│   ├── web.py        # ctfkit web send / curl / fuzz  (allowlist·속도 제한)
│   ├── workspace.py  # ctfkit workspace new / list / log / info
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
     console     flags / analysis (공용 도구)
```

## 확장 지점 1: Transform

모든 변환은 `registry.Transform` 을 상속한다. 입력·출력은 항상 `bytes`.

| 멤버 | 용도 | 기본값 |
| --- | --- | --- |
| `name`, `aliases` | 명령어에서 쓰는 이름 | (필수), `()` |
| `description` | `codec list` 설명 | `""` |
| `decode(data, key)` / `encode(data, key)` | 변환 본체. 실패하면 `TransformError` | (필수) |
| `needs_key`, `example_key` | 키가 필요한가, 예시 키 | `False`, `None` |
| `looks_like(data)` | auto 엔진이 시도할 가치가 있는지 빠른 판별 | 항상 `True` |
| `guess_keys(data, limit)` | 키 없이 키 후보 추정 (crack, auto 에서 사용) | `[]` |

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
| 라벨·순서·입력 방식 다듬기 | | 명령 파일에 `GUI_HINTS` (선택, 형식은 `gui/schema.py` 참고) |

입력 방식은 argparse 정의로 정해진다: `store_true` → 체크박스, `choices` → 목록, `type=int/float` → 숫자 칸, 위치 인자 기본값 `-` → 여러 줄 입력(stdin), `append`·`nargs='+'` → 한 줄에 값 하나. 옵션 이름이 `file`·`words`·`cookies`·`dump`·`root` 면 파일·폴더 선택 버튼이 붙는다.

`tests/test_gui_schema.py` 는 모든 명령을 순회하며 생성한 인자가 실제 argparse 를 통과하는지 검사하므로, 새 명령도 테스트를 추가하지 않아도 이 검사를 받는다.

입력과 결과가 "실행 → 텍스트 출력" 형태를 벗어나는 기능(대화형 입력, 그래프, 탭 간 결과 전달 등)은 자동 생성 범위 밖이라 `app.py` 에 전용 화면을 추가해야 한다.

## auto 엔진 (engine/search.py)

빔 서치. 매 단계마다:

1. 현재 후보마다 `looks_like` 를 통과한 모든 변환을 적용한다. 키가 필요한 변환은 `guess_keys` 결과로 시도한다. 키 없는 변환이 먼저 (같은 결과면 `rot13` 이 `caesar(13)` 보다 먼저 기록되도록).
2. 이미 본 결과(`seen`)는 버린다. 순환과 중복 방지.
3. 플래그 정규식에 맞는 결과가 나오면 그 단계에서 멈춘다 (가장 짧은 경로).
4. 아니면 점수 상위 `beam` 개만 다음 단계로 넘긴다. 이미 영어로 읽히는 후보(`SOLVED_THRESHOLD`)는 더 풀지 않는다.

최종 순위는 `rank_score = score − 0.02×단계 수 − 0.05×키 추정 단계 수`.
키를 추정한 단계는 데이터에 맞춰 고른 것이라 점수가 부풀려지는 경향(과적합)이 있어서 더 깎는다.

### 점수 (analysis.py)

- `printable_ratio`: 출력 가능한 ASCII 비율
- `english_score`: (알파벳 + 흔한 문장부호 비율) × 1/(1 + χ²/n)
- `text_score`: 바이너리면 낮게, 텍스트면 printable 과 english 의 평균
- 플래그가 있으면 1.0

## 키 추정 (crack)

| 변환 | 방법 |
| --- | --- |
| caesar | 26개 이동을 모두 시도해 카이제곱(영어 빈도와의 거리)이 작은 순 |
| vigenere | ① 일치 지수(IC)로 키 길이 후보 → ② 열마다 시저처럼 카이제곱으로 이동 칸 수 → ③ `KEYKEY` 같은 반복 키를 `KEY` 로 축약 |
| xor | ① 알려진 평문 공격: 플래그 접두사(`DH{` 등)로 시작한다고 가정해 키 계산, 여러 바이트 키 가능 → ② 1바이트 키 256개 전수 조사 후 text_score 순 |

## 참고한 기존 도구

- CyberChef의 "Magic" 연산: 여러 겹 인코딩을 자동 탐지하는 아이디어
- Ciphey: 점수 기반으로 암호·인코딩을 자동 해독하는 아이디어

위 도구들의 코드는 사용하지 않았다. ctfkit의 코드는 대부분 AI(Claude Code)가 작성하고 사람이 리뷰했다(README의 "AI 활용" 참고). 고전 암호 분석 기법(빈도 분석, 일치 지수, 알려진 평문 공격)은 교과서적인 방법이다.
