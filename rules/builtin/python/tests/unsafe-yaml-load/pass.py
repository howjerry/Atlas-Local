# 安全的 YAML 載入：不應觸發規則
# 使用 yaml.safe_load 或明確指定 SafeLoader

import yaml

def load_config_safe(config_str):
    # safe_load 只允許基本 Python 型別
    return yaml.safe_load(config_str)

def load_from_file_safe(filepath):
    with open(filepath) as f:
        data = yaml.safe_load(f)
    return data
