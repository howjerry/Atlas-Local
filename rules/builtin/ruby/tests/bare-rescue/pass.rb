# 良好：rescue 有明確指定例外類別
class DataLoader
  def load(path)
    begin
      File.read(path)
    rescue Errno::ENOENT => e
      Rails.logger.warn("File not found: #{e.message}")
      nil
    end
  end
end
