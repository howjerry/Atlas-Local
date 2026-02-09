public void Handle(HttpRequest request) {
    var path = Request.QueryString["path"];
    System.IO.File.ReadAllText(path);
}
