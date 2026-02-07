# Unsafe Deserialization: SHOULD trigger the rule
# Pattern: pickle.load/loads/dump/dumps, yaml.load/loads/dump/dumps calls
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import pickle
import yaml

def unsafe_deserialize(data, file_handle):
    obj1 = pickle.loads(data)

    obj2 = pickle.load(file_handle)

    config = yaml.load(data)

    pickle.dump(obj1, file_handle)
