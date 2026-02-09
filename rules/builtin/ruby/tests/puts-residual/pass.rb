# 良好：使用結構化日誌取代 puts
class OrderService
  def create_order(items)
    Rails.logger.info("Creating order with items")
    order = Order.new(items: items)
    Rails.logger.debug("Order: #{order.inspect}")
    order.save!
  end
end
