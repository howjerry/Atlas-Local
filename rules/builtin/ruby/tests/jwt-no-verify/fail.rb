# JWT No Verify: SHOULD trigger the rule
# Pattern: JWT.decode 跳過簽名驗證
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

require 'jwt'

# 不安全：第二個參數為 false 跳過驗證
payload = JWT.decode(token, false)

