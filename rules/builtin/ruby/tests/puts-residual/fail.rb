# 不良：殘留的 puts 除錯輸出
class OrderService
  def create_order(items)
    puts "Creating order with items"
    order = Order.new(items: items)
    puts order.inspect
    order.save!
  end
end
