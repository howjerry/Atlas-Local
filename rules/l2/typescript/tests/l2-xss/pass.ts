function handler(req, res) {
    const name = req.body.name;
    const safe = escapeHtml(name);
    res.send(safe);
}
