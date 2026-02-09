# 不良：rescue 沒有指定例外類別
class DataLoader
  def load(path)
    begin
      File.read(path)
    rescue
      nil
    end
  end
end
