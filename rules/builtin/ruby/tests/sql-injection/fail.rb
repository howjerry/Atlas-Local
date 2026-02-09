# 不安全：使用字串內插建構 SQL 查詢
class UserController
  def find_user(name)
    connection.execute("SELECT * FROM users WHERE name = '#{name}'")
  end

  def search(query)
    User.where("email LIKE '%#{query}%'")
  end

  def raw_query(id)
    User.find_by_sql("SELECT * FROM users WHERE id = #{id}")
  end
end
