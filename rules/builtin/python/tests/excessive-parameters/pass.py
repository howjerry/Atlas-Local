# 合理的參數數量：不應觸發規則
# 函式定義不超過 5 個參數

def create_user(name, email, age):
    return {"name": name, "email": email, "age": age}

def add(a, b):
    return a + b

def greet(name):
    return f"Hello, {name}!"

def process(data, config, logger, handler):
    # 4 個參數，在合理範圍內
    return data
