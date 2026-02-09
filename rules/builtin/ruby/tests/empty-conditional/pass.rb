# 良好：條件區塊有實際的邏輯
class Handler
  def process(status)
    if status == :pending
      enqueue_for_processing
    end
  end

  def check(value)
    if value <= 0
      handle_negative(value)
    end
  end
end
