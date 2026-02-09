# 多餘的布林回傳：應觸發規則
# 使用 if/else 回傳 True/False 而非直接回傳條件值

def is_adult(age):
    if age >= 18:
        return True
    else:
        return False

def is_valid(data):
    if data is not None:
        return True
    else:
        return False

def has_permission(user):
    if user.role == "admin":
        return True
    else:
        return False
