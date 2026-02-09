# 捕獲特定例外：不應觸發規則
# 使用具體的例外類型

def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return None
    except PermissionError:
        return None

def parse_json(data):
    import json
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError) as e:
        print(f"Parse error: {e}")
        return {}

def safe_division(a, b):
    try:
        return a / b
    except ZeroDivisionError:
        return None
