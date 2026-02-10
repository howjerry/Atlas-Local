# Insecure TLS: should NOT trigger the rule
# 使用正確的 TLS 設定和憑證驗證

import ssl
import requests

def safe_ssl_context():
    # 安全：使用預設的安全 SSL context
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx

def safe_requests(url):
    # 安全：requests 預設驗證憑證
    response = requests.get(url)
    return response

def safe_requests_custom_ca(url, ca_bundle):
    # 安全：使用自訂 CA bundle
    response = requests.get(url, verify=ca_bundle)
    return response

