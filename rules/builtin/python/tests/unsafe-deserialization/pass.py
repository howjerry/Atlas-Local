# Unsafe Deserialization: should NOT trigger the rule
# Uses safe alternatives like JSON or yaml.safe_load

import json
import yaml

def safe_deserialize(data, file_handle):
    obj1 = json.loads(data)

    obj2 = json.load(file_handle)

    config = yaml.safe_load(data)

    json.dump(obj1, file_handle)
