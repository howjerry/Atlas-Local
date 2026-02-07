# Eval Usage: should NOT trigger the rule
# Uses safe alternatives like ast.literal_eval or JSON parsing

import ast
import json

def safe_parse(user_input):
    result = ast.literal_eval(user_input)

    data = json.loads(user_input)

    operations = {
        "add": lambda a, b: a + b,
        "sub": lambda a, b: a - b,
    }
    fn = operations.get(user_input)
