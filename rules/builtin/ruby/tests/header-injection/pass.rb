# Header Injection: should NOT trigger the rule
# 使用硬編碼 header 值

# 安全：使用硬編碼值
response.headers['Content-Type'] = 'application/json'

# 安全：使用硬編碼 cache 設定
response.headers['Cache-Control'] = 'no-store, no-cache'

