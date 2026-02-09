# 安全的密碼管理：不應觸發規則
# 從環境變數或設定檔讀取敏感資訊

import os

def get_credentials():
    # 從環境變數讀取（安全）
    db_password = os.environ.get("DB_PASSWORD")
    api_key = os.environ.get("API_KEY")
    return db_password, api_key

# 普通字串賦值（變數名不含敏感關鍵字）
username = "admin"
host = "localhost"
port = 5432
