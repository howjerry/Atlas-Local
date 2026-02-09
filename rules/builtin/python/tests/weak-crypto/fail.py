# 弱雜湊演算法：應觸發規則
# 使用 MD5 或 SHA1 進行雜湊是不安全的

import hashlib

def hash_password_md5(password):
    # MD5 已被證明可進行碰撞攻擊
    return hashlib.md5(password.encode()).hexdigest()

def hash_data_sha1(data):
    # SHA1 已有實際碰撞攻擊案例
    return hashlib.sha1(data.encode()).hexdigest()
