public void Handle(HttpRequest request) {
    var cmd = Request.QueryString["cmd"];
    var safe = int.Parse(cmd);
    Console.WriteLine(safe);
}
