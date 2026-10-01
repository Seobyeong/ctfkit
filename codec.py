import base64

data = "ZmxhZ3toZWxsb30="

# data를 decode해서 result에 넣기
result = base64.b64decode(data)

# decode한 result를 내용만 출력
print(result.decode())
