def handler(request):
    file_path = request.form["file"]
    open(file_path)
