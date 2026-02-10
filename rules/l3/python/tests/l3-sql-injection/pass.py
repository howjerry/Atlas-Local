# L3 SQL Injection (safe): 經過 int() 淨化
def handle_search(request):
    user_id = int(request.form["id"])
    query_user(user_id)

def query_user(uid):
    sql = "SELECT * FROM users WHERE id = " + str(uid)
    cursor.execute(sql)
