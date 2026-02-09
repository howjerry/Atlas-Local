# 使用 assert 做執行時驗證：應觸發規則
# assert 在 -O 模式下會被移除

def process_order(quantity):
    assert quantity > 0
    return quantity * 10

def authenticate(username, password):
    assert username is not None
    assert len(password) >= 8
    return True

def divide(a, b):
    assert b != 0, "Divisor cannot be zero"
    return a / b
