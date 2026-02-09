def handler(request):
    cmd = request.form["cmd"]
    safe = int(cmd)
    print(safe)
