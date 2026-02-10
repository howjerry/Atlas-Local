# L3 Command Injection: 跨函數污染 — request.form → arg → subprocess.run
# 注意：此為 SAST 偵測用測試夾具
def handle_action(request):
    cmd = request.form["command"]
    run_task(cmd)

def run_task(command):
    subprocess.run(command)
