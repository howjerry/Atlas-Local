# 捕獲過於寬泛的例外：應觸發規則
# 使用 except Exception 捕獲所有例外

def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return None

def parse_json(data):
    try:
        import json
        return json.loads(data)
    except Exception as e:
        print(f"Error: {e}")
        return {}

def connect_db(url):
    try:
        db = create_connection(url)
        return db
    except Exception:
        return None
