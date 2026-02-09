# 不良：在正式環境程式碼中使用 sleep
class RetryService
  def call_api(url)
    response = fetch(url)
    unless response.ok?
      sleep(5)
      response = fetch(url)
    end
    response
  end

  def poll_status
    loop do
      break if done?
      sleep 2
    end
  end
end
