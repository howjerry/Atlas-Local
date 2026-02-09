# 安全：使用參數化查詢
class UserController
  def find_user(name)
    User.where(name: name)
  end

  def search(query)
    User.where("email LIKE ?", "%#{query}%")
  end

  def raw_query(id)
    User.where(id: id).first
  end
end
