# 良好：使用類別實例變數取代類別變數
class Vehicle
  class << self
    attr_accessor :count
  end
  self.count = 0

  def initialize
    self.class.count += 1
  end
end

class Car < Vehicle
  WHEELS = 4
end
