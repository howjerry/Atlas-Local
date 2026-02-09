# 良好：使用具名常數取代魔術數字
class PriceCalculator
  TAX_RATE_PERCENT = 8
  DISCOUNT_PERCENT = 15
  RETRY_INTERVAL_SECONDS = 30

  def calculate_tax(price)
    price * tax_rate(TAX_RATE_PERCENT)
  end

  def apply_discount(total)
    total - discount_amount(DISCOUNT_PERCENT)
  end
end
