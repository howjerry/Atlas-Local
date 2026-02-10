# Unsafe Reflection: SHOULD trigger the rule
# Pattern: 使用 send/constantize 搭配變數參數
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

# 不安全：使用變數呼叫 send
method_name = params[:action]
user.send(method_name)

# 不安全：使用 public_send 搭配變數
object.public_send(action)

# 不安全：使用 constantize 動態載入類別
klass = params[:type].constantize

