function handler(req) {
    const url = req.body.url;
    const safe = encodeURIComponent(url);
    console.log(safe);
}
