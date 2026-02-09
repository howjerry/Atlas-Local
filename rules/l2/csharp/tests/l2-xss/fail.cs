public void Handle(HttpRequest request) {
    var name = Request.Form["name"];
    Response.Write(name);
}
