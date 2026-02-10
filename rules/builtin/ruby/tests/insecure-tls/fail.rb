# Insecure TLS: SHOULD trigger the rule
# Pattern: 停用 SSL 憑證驗證
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

require 'net/http'
require 'openssl'

# 不安全：停用 SSL 憑證驗證
http = Net::HTTP.new('example.com', 443)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_NONE

