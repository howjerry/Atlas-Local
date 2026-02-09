# 不安全：使用已被破解的雜湊演算法
require "digest"

class TokenService
  def hash_password(password)
    Digest::MD5.hexdigest(password)
  end

  def generate_token(data)
    Digest::SHA1.hexdigest(data)
  end
end
