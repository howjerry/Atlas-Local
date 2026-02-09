# 不良：空的條件區塊
class Handler
  def process(status)
    if status == :pending
    end
  end

  def check(value)
    if value > 0
    else
      handle_negative(value)
    end
  end
end
