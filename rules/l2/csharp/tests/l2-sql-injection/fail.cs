public void Handle(HttpRequest request) {
    var name = Request.QueryString["name"];
    new SqlCommand(name);
}
