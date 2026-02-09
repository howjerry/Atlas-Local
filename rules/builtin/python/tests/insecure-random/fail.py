# 不安全的隨機數生成：應觸發規則
# 使用 random 模組產生安全相關數值是不安全的

import random

def generate_token():
    # 使用 random 產生 token（不安全）
    return random.randint(100000, 999999)

def generate_password(length):
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return random.choice(alphabet)

def pick_random_items(items):
    return random.sample(items, 3)

def get_random_float():
    return random.random()
