# 不安全：使用字串內插開啟檔案路徑
class FileService
  def read_file(filename)
    File.read("/uploads/#{filename}")
  end

  def open_file(path)
    File.open("/data/#{path}")
  end
end
