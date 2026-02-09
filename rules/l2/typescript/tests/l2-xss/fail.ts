function handler(req, res) {
    const name = req.body.name;
    res.send(name);
}
