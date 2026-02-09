# 不良：方法參數過多
class Report
  def generate(title, author, date, category, format, output_path)
    # 參數過多，不易維護
  end

  def create_user(name, email, age, phone, address, role)
    # 應使用參數物件
  end
end
