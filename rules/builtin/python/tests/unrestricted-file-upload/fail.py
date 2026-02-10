# Unrestricted File Upload: SHOULD trigger the rule
# Pattern: 上傳檔案未經驗證直接儲存
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

from flask import request

def unsafe_upload():
    uploaded = request.files["file"]
    # 不安全：直接使用原始檔名儲存
    uploaded.save(filename)

def unsafe_write(file_obj, path):
    # 不安全：直接寫入未驗證的路徑
    file_obj.write(path)

