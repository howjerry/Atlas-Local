# L3 跨檔案污染：service 接收未淨化的輸入並直接傳入 cursor.execute
# 注意：此為 SAST 偵測用測試夾具
def find_user(username):
    sql = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(sql)
