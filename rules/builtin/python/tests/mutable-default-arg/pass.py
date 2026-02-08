from typing import Optional, Dict, List

def add_item(item, items=None):
    if items is None:
        items = []
    items.append(item)
    return items

def update_config(key, value, config=None):
    if config is None:
        config = {}
    config[key] = value
    return config
