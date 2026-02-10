# L3 Command Injection (safe): 經過 shlex.quote 淨化
def handle_action(request):
    cmd = shlex.quote(request.form["command"])
    run_task(cmd)

def run_task(command):
    subprocess.run(command)
