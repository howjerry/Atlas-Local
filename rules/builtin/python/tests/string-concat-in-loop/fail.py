# 迴圈中字串串接：應觸發規則
# 在 for/while 迴圈中使用 += 串接字串

def build_csv(rows):
    result = ""
    for row in rows:
        result += row + "\n"
    return result

def collect_names(users):
    names = ""
    for user in users:
        names += user.name + ", "
    return names

def read_chunks(stream):
    data = ""
    while True:
        chunk = stream.read(1024)
        data += chunk
