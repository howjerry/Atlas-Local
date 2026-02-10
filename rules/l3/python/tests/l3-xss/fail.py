# L3 XSS: 跨函數污染 — request.args → arg → render_template_string
# 注意：此為 SAST 偵測用測試夾具
def handle_search(request):
    query = request.args["q"]
    render_result(query)

def render_result(content):
    render_template_string("<h1>" + content + "</h1>")
