def handler(request):
    id_val = request.form["id"]
    safe_id = int(id_val)
    cursor.execute(str(safe_id))
