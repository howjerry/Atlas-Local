# 不良：使用魔術數字
class PriceCalculator
  def calculate_tax(price)
    price * tax_rate(8)
  end

  def apply_discount(total)
    total - discount_amount(15)
  end

  def retry_request
    sleep(30)
  end
end
