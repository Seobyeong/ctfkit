import base64


def decode_base64(data):
    # data를 decode해서 result에 넣기
    result = base64.b64decode(data)

    # decode한 result를 내용만 반환
    return result.decode()

def decode_hex(data):
    result = bytes.fromhex(data)

    return result.decode()
