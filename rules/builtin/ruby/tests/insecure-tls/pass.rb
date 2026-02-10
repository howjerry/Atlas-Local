# Insecure TLS: should NOT trigger the rule
# 使用正確的 SSL 憑證驗證

require 'net/http'
require 'openssl'

# 安全：啟用 SSL 憑證驗證
http = Net::HTTP.new('example.com', 443)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_PEER

