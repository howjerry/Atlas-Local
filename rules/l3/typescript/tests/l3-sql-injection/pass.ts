// L3 SQL Injection (safe): 經過 sanitizer 淨化後傳入
function handleRequest(req, res) {
    const id = parseInt(req.body.id);
    queryUser(id);
}

function queryUser(userId) {
    const sql = "SELECT * FROM users WHERE id = " + userId;
    db.query(sql);
}
