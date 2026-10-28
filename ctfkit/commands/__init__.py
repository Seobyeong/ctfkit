"""서브커맨드 모음. 이 폴더의 모든 모듈은 cli.py 가 자동으로 불러온다.

각 모듈은 register(subparsers) 함수를 하나 제공해야 하며,
그 안에서 서브커맨드를 만들고 set_defaults(func=...) 로 실행 함수를 지정한다.
"""
