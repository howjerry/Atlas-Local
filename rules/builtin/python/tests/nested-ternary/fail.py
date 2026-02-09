# 巢狀三元運算子：應觸發規則
# 在條件表達式內嵌套另一個條件表達式

def classify(value):
    # 巢狀三元運算子，難以閱讀
    result = "high" if value > 100 else "medium" if value > 50 else "low"
    return result

def get_label(score):
    label = "A" if score >= 90 else "B" if score >= 80 else "C"
    return label
