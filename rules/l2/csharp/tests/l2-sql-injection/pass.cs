public void Handle(HttpRequest request) {
    var id = Request.QueryString["id"];
    var safeId = int.Parse(id);
    Console.WriteLine(safeId);
}
