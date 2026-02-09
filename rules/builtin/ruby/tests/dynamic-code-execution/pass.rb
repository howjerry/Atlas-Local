# 安全：使用 public_send 搭配允許清單取代 eval
class SafeProcessor
  ALLOWED_METHODS = %w[upcase downcase strip].freeze

  def process(method_name, value)
    raise "Method not allowed" unless ALLOWED_METHODS.include?(method_name)
    value.public_send(method_name)
  end
end
