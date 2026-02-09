def handler(request):
    file_path = request.form["file"]
    safe = int(file_path)
    print(safe)
