# L3 跨檔案污染：view 從 request.form 取得使用者輸入，
# 透過 import 的 service 函數傳遞到 cursor.execute sink
# 注意：此為 SAST 偵測用測試夾具
from services import find_user

def handle_search(request):
    name = request.form["name"]
    user = find_user(name)
    return jsonify(user)
