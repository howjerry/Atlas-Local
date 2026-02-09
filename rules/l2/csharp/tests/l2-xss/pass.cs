public void Handle(HttpRequest request) {
    var name = Request.Form["name"];
    var safe = HtmlEncoder.Encode(name);
    Response.Write(safe);
}
