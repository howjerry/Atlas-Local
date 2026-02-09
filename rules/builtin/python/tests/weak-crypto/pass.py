# 安全的雜湊演算法：不應觸發規則
# 使用 SHA-256 或更強的演算法

import hashlib

def hash_data_sha256(data):
    # SHA-256 是目前推薦的雜湊演算法
    return hashlib.sha256(data.encode()).hexdigest()

def hash_data_sha3(data):
    return hashlib.sha3_256(data.encode()).hexdigest()

def hash_with_pbkdf2(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
