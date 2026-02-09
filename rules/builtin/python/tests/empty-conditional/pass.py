# 非空的條件區塊：不應觸發規則
# if 區塊有實際的邏輯處理

def check_value(x):
    if x > 10:
        print("Value exceeds threshold")

def process_data(data):
    if data is None:
        return []
    return data

def categorize(value):
    if value > 100:
        return "high"
    return "low"
