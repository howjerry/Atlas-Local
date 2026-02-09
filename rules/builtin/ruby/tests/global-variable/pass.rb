# 良好：使用模組常數或類別屬性取代全域變數
module AppConfig
  SETTINGS = { debug: true }.freeze
end

class Tracker
  class << self
    attr_accessor :counter
  end
  self.counter = 0

  def increment
    self.class.counter += 1
  end
end
