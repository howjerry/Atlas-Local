public void Handle(HttpRequest request) {
    var url = Request.QueryString["url"];
    var safe = new Uri(url, UriKind.RelativeOrAbsolute);
    if (safe.IsAbsoluteUri && safe.Scheme == "https") {
        using (var client = new HttpClient()) {
            client.GetAsync(safe);
        }
    }
}
