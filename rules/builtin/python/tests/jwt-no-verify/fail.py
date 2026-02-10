# JWT No Verify: SHOULD trigger the rule
# Pattern: jwt.decode 跳過簽名驗證
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import jwt

def unsafe_decode_no_verify(token):
    # 不安全：使用 options 停用簽名驗證
    payload = jwt.decode(token, options={"verify_signature": False})
    return payload

def unsafe_decode_algorithms(token):
    # 不安全：使用 algorithms=["none"]
    payload = jwt.decode(token, algorithms=["none"])
    return payload

