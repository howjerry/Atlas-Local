# Unrestricted File Upload: should NOT trigger the rule
# 使用安全的檔案處理方式

from werkzeug.utils import secure_filename
import os

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

def safe_upload(file):
    # 安全：使用 secure_filename 並驗證副檔名
    filename = secure_filename(file.filename)
    ext = filename.rsplit(".", 1)[1].lower()
    if ext in ALLOWED_EXTENSIONS:
        safe_path = os.path.join("/uploads", filename)
        file.save(safe_path)

