# 安全：使用強雜湊演算法
require "digest"
require "bcrypt"

class TokenService
  def hash_data(data)
    Digest::SHA256.hexdigest(data)
  end

  def hash_password(password)
    BCrypt::Password.create(password)
  end
end
