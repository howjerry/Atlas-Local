# Insecure TLS: SHOULD trigger the rule
# Pattern: 停用 TLS 憑證驗證或使用不安全的 SSL context
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import ssl
import requests

def unsafe_unverified_context():
    # 不安全：建立不驗證憑證的 SSL context
    ctx = ssl._create_unverified_context()
    return ctx

def unsafe_requests_no_verify(url):
    # 不安全：requests 停用憑證驗證
    response = requests.get(url, verify=False)
    return response

def unsafe_post_no_verify(url, data):
    # 不安全：POST 停用憑證驗證
    response = requests.post(url, verify=False)
    return response

