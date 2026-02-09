# 正確的執行時驗證：不應觸發規則
# 使用明確的條件判斷與例外處理

def process_order(quantity):
    if quantity <= 0:
        raise ValueError("Quantity must be positive")
    return quantity * 10

def authenticate(username, password):
    if username is None:
        raise ValueError("Username is required")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    return True

def divide(a, b):
    if b == 0:
        raise ZeroDivisionError("Divisor cannot be zero")
    return a / b
