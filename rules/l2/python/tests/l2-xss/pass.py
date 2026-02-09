def handler(request):
    name = request.form["name"]
    safe = bleach.clean(name)
    response.write(safe)
