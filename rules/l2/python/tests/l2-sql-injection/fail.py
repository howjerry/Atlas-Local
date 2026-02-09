def handler(request):
    name = request.form["name"]
    cursor.execute(name)
