# 不良：使用類別變數，在繼承體系中行為不可預期
class Vehicle
  @@count = 0

  def initialize
    @@count += 1
  end
end

class Car < Vehicle
  @@wheels = 4
end
