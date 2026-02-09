# 良好：使用 keyword arguments 或參數物件
class Report
  def generate(title:, options: {})
    author = options[:author]
    format = options[:format]
  end

  def create_user(attrs)
    User.new(attrs)
  end
end
