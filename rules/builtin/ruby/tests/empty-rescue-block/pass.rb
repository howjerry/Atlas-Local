# 良好：rescue 區塊有適當的錯誤處理
class DataProcessor
  def process(data)
    begin
      parse(data)
    rescue StandardError => e
      Rails.logger.error("Parse failed: #{e.message}")
      nil
    end
  end
end
