def handler(request):
    url = request.form["url"]
    safe = int(url)
    print(safe)
