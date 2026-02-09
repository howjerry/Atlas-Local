# 良好：使用重試函式庫取代 sleep
require "retriable"

class RetryService
  def call_api(url)
    Retriable.retriable(tries: 3, base_interval: 1.0) do
      response = fetch(url)
      raise "Request failed" unless response.ok?
      response
    end
  end

  def poll_status
    Timeout.timeout(30) do
      loop do
        break if done?
        Thread.pass
      end
    end
  end
end
