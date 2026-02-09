# 安全：從環境變數讀取敏感資訊
class AppConfig
  def setup
    password = ENV.fetch("DB_PASSWORD")
    api_key = ENV.fetch("API_KEY")
    secret_key = Rails.application.credentials.secret_key_base
  end
end
