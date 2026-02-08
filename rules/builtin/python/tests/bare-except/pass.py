def safe_division(a, b):
    if b == 0:
        return None
    return a / b

def proper_handling():
    try:
        result = 1 / 0
    except ZeroDivisionError:
        return None
