# JWT No Verify: should NOT trigger the rule
# 使用正確的簽名驗證

import jwt

SECRET_KEY = "your-secret-key"

def safe_decode(token):
    # 安全：使用密鑰和演算法驗證
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    return payload

def safe_decode_rsa(token, public_key):
    # 安全：使用 RSA 公鑰驗證
    payload = jwt.decode(token, public_key, algorithms=["RS256"])
    return payload

