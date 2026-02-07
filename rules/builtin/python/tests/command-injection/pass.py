# Command Injection: should NOT trigger the rule
# Uses safe subprocess patterns without shell=True

import shlex
import pathlib

def safe_commands(user_input):
    # Using list form with no shell
    result = ["ls", "-la", user_input]

    # Using pathlib for file operations
    path = pathlib.Path(user_input)
    files = list(path.iterdir())

    # Using shlex.quote for safe quoting
    safe_input = shlex.quote(user_input)
