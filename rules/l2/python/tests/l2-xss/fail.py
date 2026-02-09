def handler(request):
    name = request.form["name"]
    response.write(name)
