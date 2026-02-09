# 不良：空的 rescue 區塊，默默吞掉例外
class DataProcessor
  def process(data)
    begin
      parse(data)
    rescue StandardError
    end
  end
end
