# Command Injection: should NOT trigger the rule
# Uses safe subprocess patterns without shell=True

import shlex
import subprocess
import pathlib

def safe_commands(user_input):
    # subprocess list form（無 shell=True）— 安全用法
    subprocess.run(["ls", "-la", user_input])

    subprocess.call(["grep", user_input, "/var/log/app.log"])

    subprocess.check_output(["echo", user_input])

    subprocess.Popen(["cat", user_input], stdout=subprocess.PIPE)

    # Using pathlib for file operations
    path = pathlib.Path(user_input)
    files = list(path.iterdir())

    # Using shlex.quote for safe quoting
    safe_input = shlex.quote(user_input)
