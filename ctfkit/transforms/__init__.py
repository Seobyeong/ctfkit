"""변환 플러그인 모음. 이 폴더의 모든 모듈은 registry.discover() 가 자동으로 불러온다.

새 변환 추가 방법:
    1. 이 폴더에 파일을 만든다 (예: rot13.py)
    2. Transform 을 상속하고 @register 를 붙인다
    3. tests/test_transforms.py 에 정답 벡터를 추가한다
"""
