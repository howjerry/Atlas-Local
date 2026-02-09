# 安全：驗證路徑在允許的目錄範圍內
class FileService
  BASE_DIR = "/uploads"

  def read_file(filename)
    safe_path = File.expand_path(filename, BASE_DIR)
    raise "Invalid path" unless safe_path.start_with?(BASE_DIR)
    File.read(safe_path)
  end
end
