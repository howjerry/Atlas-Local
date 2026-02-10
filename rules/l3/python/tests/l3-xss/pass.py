# L3 XSS (safe): 經過 escape() 淨化
def handle_search(request):
    query = escape(request.args["q"])
    render_result(query)

def render_result(content):
    render_template_string("<h1>" + content + "</h1>")
