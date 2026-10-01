**2026/10/01**
- codec.py를 작성하는 과정에서 b64decode를 통해서 인코딩된 data를 result에 디코딩해서 넣었지만 결과값을 출력할 경우 앞에 b가 붙는 경우가 발생.
    - 이를 해결하기 위해서 result뒤에 .decode()를 붙여서 해결
    - 문제 원인은 b64decode의 반환값이 byte형식이기에 그런 것.
    - decode는 byte형식을 str형식으로 바꿔주기에 문제가 해결되었음


