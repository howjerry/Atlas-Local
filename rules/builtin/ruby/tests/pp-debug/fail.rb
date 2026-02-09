# 不良：殘留的 pp 除錯輸出
class OrderProcessor
  def process(order)
    pp order
    validate(order)
    pp order.items
    save(order)
  end
end
