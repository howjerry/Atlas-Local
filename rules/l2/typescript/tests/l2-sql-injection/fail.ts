function handler(req) {
    const name = req.body.name;
    db.query(name);
}
