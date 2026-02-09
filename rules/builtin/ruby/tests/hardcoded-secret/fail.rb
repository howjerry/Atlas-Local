# 不安全：在原始碼中硬編碼密碼與密鑰
class AppConfig
  def setup
    password = "super_secret_123"
    api_key = "sk-1234567890abcdef"
    secret_key = "my_secret_key_value"
    auth_token = "bearer_token_hardcoded"
  end
end
