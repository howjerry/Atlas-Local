# 良好：使用 if/elsif/else 取代巢狀三元運算式
class Classifier
  def categorize(score)
    if score > 95
      "excellent"
    elsif score > 90
      "great"
    else
      "average"
    end
  end

  def label(value)
    if value > 100
      "high"
    elsif value > 0
      "medium"
    else
      "low"
    end
  end
end
