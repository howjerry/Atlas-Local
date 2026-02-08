def ignore_errors():
    try:
        result = int("invalid")
    except ValueError:
        pass

def suppress_all():
    try:
        data = open("missing.txt").read()
    except FileNotFoundError:
        pass
