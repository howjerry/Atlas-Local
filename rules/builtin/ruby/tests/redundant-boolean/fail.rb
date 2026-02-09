# 不良：在條件式中多餘地回傳布林值
class Validator
  def adult?(age)
    if age >= 18
      true
    else
      false
    end
  end

  def valid_email?(email)
    if email.include?("@")
      true
    else
      false
    end
  end
end
