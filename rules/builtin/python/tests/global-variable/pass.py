# 不使用 global：不應觸發規則
# 使用參數傳遞與回傳值

def increment(counter):
    # 透過參數傳遞並回傳新值
    return counter + 1

def update_config(config, key, value):
    new_config = dict(config)
    new_config[key] = value
    return new_config

class Counter:
    def __init__(self):
        self.value = 0

    def increment(self):
        self.value += 1
