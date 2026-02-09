def handler(request):
    cmd = request.form["cmd"]
    subprocess.run(cmd)
