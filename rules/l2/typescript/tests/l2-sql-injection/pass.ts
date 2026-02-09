function handler(req) {
    const id = req.body.id;
    const safeId = parseInt(id);
    db.query(safeId);
}
