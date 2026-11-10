"""서브커맨드 모음. 이 폴더의 모든 모듈은 cli.py 가 자동으로 불러온다.

각 모듈은 register(subparsers) 함수를 하나 제공해야 하며,
그 안에서 서브커맨드를 만들고 set_defaults(func=...) 로 실행 함수를 지정한다.
"""

# 명령 이름이 파일 이름과 다를 때만 적는다 (명령 이름 → 모듈 이름).
# cli.py 가 실행할 명령의 모듈만 불러오는 데(지연 로딩) 쓴다. 여기 없고 파일 이름과도 다른
# 명령은 그래도 동작하지만 모든 모듈을 불러오느라 느리다. tests/test_lazy_v022.py 가 빠진 항목을 잡는다.
ALIASES = {
    "hash": "hashes",      # hashlib 와 헷갈리지 않게 파일 이름은 hashes
    "base": "numbase",     # base64 등과 헷갈리지 않게 파일 이름은 numbase
    "ws": "workspace",     # workspace 의 줄임 명령
}
