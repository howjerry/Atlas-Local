# 安全的 HTTP 請求：不應觸發規則
# 使用硬編碼的 URL 字串

import requests

def fetch_api_data():
    # 使用硬編碼的安全 URL
    response = requests.get("https://api.example.com/data")
    return response.json()

def health_check():
    response = requests.get("https://internal.example.com/health")
    return response.status_code == 200
