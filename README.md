# ctfkit

드림핵(Dreamhack) 워게임 학습을 위한 CTF 보조 CLI 도구.
인코딩/디코딩과 고전 암호 해독부터 HTTP 요청(curl 재현)·브루트포스·파일 분석까지,
CTF 풀이에 반복되는 작업 대부분을 터미널에서 명령어 하나로 처리하는 올인원 도구를 목표로 합니다.

> 📚 오픈소스소프트웨어 수업 텀 프로젝트로 개발 중입니다. CTF/워게임 학습 과정에서
> 반복적으로 필요했던 작업들을 직접 도구로 만들어 가며 배웁니다.
> 설계·리뷰에 AI(Claude)를 활용했고, 핵심 로직은 직접 작성합니다.

## 상태

진행 중 — 암호 계열(`codec`·`auto`·`crack`)은 동작하며, 나머지 모듈을 순차적으로 붙이는 중입니다.

- ✅ **동작:** `codec`, `auto`, `crack` + 플러그인 레지스트리, pytest, GitHub Actions CI(커버리지 97%)
- 🚧 **개발 예정:** `web`, `hash`, `forensic`, `workspace`

자세한 계획과 진행 상황은 [docs/ROADMAP.md](docs/ROADMAP.md)를 참고하세요.

## 기능

| 모듈 | 설명 | 상태 |
| --- | --- | --- |
| `codec` | 인코딩/디코딩 (base64, base32, hex, URL, ROT13, XOR) | ✅ |
| `auto` | 여러 겹으로 인코딩된 문자열을 자동 추정해 단계별로 복원 | ✅ |
| `crack` | 키 없이 고전 암호(시저·비즈네르·XOR) 해독 | ✅ |
| `web` | 워게임 서버 대상 HTTP 요청·curl 재현·반복·파라미터 퍼징 | 🚧 |
| `hash` | 해시 종류 판별, 사전 기반 브루트포스, HMAC 계산 | 🚧 |
| `forensic` | 파일 형식 판별, 문자열 추출, 숨은 파일·LSB 탐지 | 🚧 |
| `workspace` | 문제별 작업 폴더·명령 기록·풀이 노트 관리 | 🚧 |

## 사용 예시

동작하는 기능:

```
$ ctfkit codec decode base64 "ZmxhZ3toZWxsb30="
flag{hello}

$ ctfkit auto "NjY2YzYxNjc3YjY4Njk3ZA=="
[1] base64 -> 666c61677b68697d
[2] hex    -> flag{hi}
```

개발 예정(목표) 기능:

```
# HTTP 요청 반복 / 파라미터 퍼징 (allowlist 대상에만)
$ ctfkit web fuzz "http://localhost:8000/?id=FUZZ" --words ids.txt

# 해시 종류 판별 + 사전 기반 브루트포스
$ ctfkit hash crack 5f4dcc3b5aa765d61d8327deb882cf99 --words words.txt
```

## ⚠️ 사용 범위와 윤리 (중요)

이 도구, 특히 `web`·`hash` 등 요청/대입 기능은 **학습 목적으로만** 사용합니다.

- **허가된 대상에만 사용합니다.** 드림핵이 문제로 제공한 워게임 인스턴스, `localhost`,
  본인이 직접 띄운 실습 서버만 대상으로 합니다.
- 허용 도메인 목록(allowlist)에 없는 주소로는 요청을 보내지 않도록 설계합니다.
- 드림핵 사이트 본체(로그인·채점·플래그 제출)를 자동화하지 않습니다.
- 요청 반복·브루트포스 기능에는 속도 제한과 총량 상한을 둡니다.
- 허가받지 않은 시스템에 대한 사용은 불법일 수 있으며, 그 책임은 사용자에게 있습니다.

## 참고한 도구

설계·아이디어 면에서 다음 오픈소스/도구를 참고했습니다. 코드는 직접 작성했습니다.

- [CyberChef](https://github.com/gchq/CyberChef) "Magic" — 자동 디코딩 아이디어
- [Ciphey](https://github.com/Ciphey/Ciphey) — 다단계 복호화 탐색
- `curl` — HTTP 요청 인터페이스 참고
- [binwalk](https://github.com/ReFirmLabs/binwalk) — 파일 분석(`forensic`) 방향

## 개발 메모

개발 과정 일지는 [docs/devlog.md](docs/devlog.md)에 기록합니다.

## 라이선스

[MIT](LICENSE)
