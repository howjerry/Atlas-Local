# 良好：直接回傳條件式結果
class Validator
  def adult?(age)
    age >= 18
  end

  def valid_email?(email)
    email.include?("@")
  end
end
