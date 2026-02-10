# Unrestricted File Upload: should NOT trigger the rule
# 使用 Active Storage 或經驗證的上傳處理

# 安全：使用 Active Storage
user.avatar.attach(params[:avatar])

# 安全：使用隨機檔名
safe_name = SecureRandom.uuid + '.jpg'
File.open(Rails.root.join('uploads', safe_name), 'wb') do |f|
  f.write(validated_content)
end

