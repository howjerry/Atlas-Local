# 非巢狀條件運算：不應觸發規則
# 使用 if/elif/else 或單層三元運算子

def classify(value):
    # 使用明確的 if/elif/else
    if value > 100:
        return "high"
    elif value > 50:
        return "medium"
    else:
        return "low"

def is_positive(x):
    # 單層三元運算子是可接受的
    return "positive" if x > 0 else "non-positive"
