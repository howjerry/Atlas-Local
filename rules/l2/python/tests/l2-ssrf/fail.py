def handler(request):
    url = request.form["url"]
    requests.get(url)
