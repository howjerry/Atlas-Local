# 良好：使用結構化日誌取代 pp
class OrderProcessor
  def process(order)
    Rails.logger.debug("Processing order: #{order.id}")
    validate(order)
    Rails.logger.debug("Items: #{order.items.count}")
    save(order)
  end
end
