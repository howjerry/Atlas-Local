# 直接回傳條件值：不應觸發規則
# 不需要 if/else 包裝布林值

def is_adult(age):
    return age >= 18

def is_valid(data):
    return data is not None

def has_permission(user):
    return user.role == "admin"

# 回傳非布林值的 if/else 是合理的
def get_status(active):
    if active:
        return "enabled"
    else:
        return "disabled"
