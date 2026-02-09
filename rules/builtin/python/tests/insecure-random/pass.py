# 安全的隨機數生成：不應觸發規則
# 使用 secrets 模組產生安全相關數值

import secrets

def generate_token():
    # 使用 secrets 產生安全的 token
    return secrets.token_hex(16)

def generate_password(length):
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return secrets.choice(alphabet)

def get_secure_number():
    return secrets.randbelow(1000000)
