# 過多參數：應觸發規則
# 函式定義有 6 個或以上的參數

def create_user(name, email, age, address, phone, role):
    # 6 個參數，過多
    return {"name": name, "email": email, "age": age}

def send_notification(recipient, subject, body, cc, bcc, priority, attachments):
    # 7 個參數，過多
    pass

def connect_database(host, port, user, password, database, charset):
    # 6 個參數，過多
    pass
