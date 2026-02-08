def add_item(item, items=[]):
    items.append(item)
    return items

def update_config(key, value, config={}):
    config[key] = value
    return config
