# JWT No Verify: should NOT trigger the rule
# 使用正確的 JWT 簽名驗證

require 'jwt'

# 安全：使用金鑰驗證簽名
payload = JWT.decode(token, secret_key, true, algorithm: 'HS256')

# 安全：使用 RSA 公鑰驗證
payload = JWT.decode(token, rsa_public_key, true, algorithms: ['RS256'])

