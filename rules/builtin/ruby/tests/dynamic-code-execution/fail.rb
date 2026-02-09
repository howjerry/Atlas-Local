# 不安全：使用 eval 執行動態程式碼（此為 SAST 規則測試夾具，故意展示不安全寫法）
class DynamicProcessor
  def process(expression)
    eval(expression)
  end

  def evaluate_in_context(code)
    instance_eval(code)
  end
end
