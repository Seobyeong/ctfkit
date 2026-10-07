import sys

import codec

if len(sys.argv) < 2:
    print('문자열을 입력해주세요')
    sys.exit(1)
print(codec.decode_base64(sys.argv[1]))