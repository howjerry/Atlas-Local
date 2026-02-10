# Header Injection: SHOULD trigger the rule
# Pattern: HTTP response header 使用字串內插
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

# 不安全：header 值使用字串內插
response.headers['X-Custom'] = "value: #{params[:data]}"

# 不安全：使用 add_header 搭配字串內插
response.add_header('X-Token', "#{user_token}")

