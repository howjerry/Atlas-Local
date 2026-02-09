public void Handle(HttpRequest request) {
    var filename = Request.QueryString["file"];
    var safe = System.IO.Path.GetFileName(filename);
    System.IO.File.ReadAllText(safe);
}
