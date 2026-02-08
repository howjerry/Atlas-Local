def risky_operation():
    try:
        result = 1 / 0
    except:
        pass

def another_risky():
    try:
        data = open("file.txt").read()
    except:
        return None
