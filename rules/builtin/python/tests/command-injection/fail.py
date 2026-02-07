# Command Injection: SHOULD trigger the rule
# Pattern: os.system/os.popen/subprocess.call/run/Popen/check_call/check_output calls
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import os
import subprocess

def unsafe_commands(user_input):
    os.system(user_input)

    os.popen("ls " + user_input)

    subprocess.call(user_input, shell=True)

    subprocess.run(f"grep {user_input} /var/log/app.log", shell=True)

    subprocess.check_output(user_input)
