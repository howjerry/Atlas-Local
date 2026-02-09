# 高效的字串建構：不應觸發規則
# 使用 list + join 來建構字串

def build_csv(rows):
    # 使用 join 組合字串（高效）
    return "\n".join(rows)

def collect_names(users):
    # 使用 list comprehension + join
    return ", ".join(user.name for user in users)

def read_chunks(stream):
    # 使用 list 收集片段
    parts = []
    while True:
        chunk = stream.read(1024)
        parts.append(chunk)
    return "".join(parts)

# 迴圈外的 += 是可接受的
message = "Hello"
message += " World"
