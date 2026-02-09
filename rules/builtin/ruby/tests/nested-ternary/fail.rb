# 不良：巢狀三元運算式，難以閱讀
class Classifier
  def categorize(score)
    score > 90 ? (score > 95 ? "excellent" : "great") : "average"
  end

  def label(value)
    value > 0 ? (value > 100 ? "high" : "medium") : "low"
  end
end
