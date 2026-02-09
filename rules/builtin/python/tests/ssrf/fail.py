# SSRF 漏洞：應觸發規則
# 使用變數作為 URL 傳遞給 requests 函式

import requests

def fetch_url(url):
    # 將使用者提供的 URL 直接傳遞給 requests（不安全）
    response = requests.get(url)
    return response.text

def proxy_request(target_url):
    return requests.post(target_url)

def update_webhook(webhook_url):
    return requests.put(webhook_url)
