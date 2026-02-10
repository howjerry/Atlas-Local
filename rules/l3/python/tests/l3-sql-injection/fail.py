# L3 SQL Injection: 跨函數污染 — request.form → arg → cursor.execute
# 注意：此為 SAST 偵測用測試夾具
def handle_search(request):
    name = request.form["name"]
    query_user(name)

def query_user(username):
    sql = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(sql)
