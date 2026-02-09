public void Handle(HttpRequest request) {
    var url = Request.QueryString["url"];
    using (var client = new HttpClient()) {
        client.GetAsync(url);
    }
}
