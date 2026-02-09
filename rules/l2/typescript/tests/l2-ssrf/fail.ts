function handler(req) {
    const url = req.body.url;
    fetch(url);
}
