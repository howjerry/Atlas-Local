# Unrestricted File Upload: SHOULD trigger the rule
# Pattern: 使用 original_filename 直接儲存上傳檔案
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

# 不安全：使用原始檔名直接儲存
uploaded = params[:file]
File.open(uploaded.original_filename, 'wb') do |f|
  f.write(uploaded.read)
end

# 不安全：使用 FileUtils 複製暫存檔
FileUtils.cp(uploaded.tempfile, destination)

