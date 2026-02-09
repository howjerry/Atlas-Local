# 使用 global 陳述句：應觸發規則
# 在函式中使用 global 修改模組層級變數

counter = 0
config = {}

def increment():
    global counter
    counter += 1

def update_config(key, value):
    global config
    config[key] = value

def reset():
    global counter
    counter = 0
