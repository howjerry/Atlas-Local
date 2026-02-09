# 使用者服務類別
class UserService
  # 根據 ID 查詢使用者
  def find_user(id)
    User.find(id)
  end

  # 計算使用者總數
  def count_users
    User.count
  end
end
