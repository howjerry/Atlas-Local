# 不良：使用全域變數
$app_config = { debug: true }
$counter = 0

class Tracker
  def increment
    $counter += 1
  end
end
