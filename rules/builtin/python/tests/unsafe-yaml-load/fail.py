# 不安全的 YAML 載入：應觸發規則
# 使用 yaml.load() 而未指定安全的 Loader

import yaml

def load_config(config_str):
    # yaml.load 預設使用不安全的 FullLoader
    return yaml.load(config_str)

def load_from_file(filepath):
    with open(filepath) as f:
        data = yaml.load(f)
    return data
