# Eval Usage: SHOULD trigger the rule
# Pattern: eval() or exec() calls with arguments
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

def unsafe_eval(user_input):
    result = eval(user_input)

    eval("print('hello ' + " + user_input + ")")

    exec(user_input)

    exec("import os; os.remove('" + filename + "')")
