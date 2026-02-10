// L3 SQL Injection: 跨函數污染 — req.body → arg → db.query
function handleRequest(req, res) {
    const name = req.body.name;
    queryUser(name);
}

function queryUser(username) {
    const sql = "SELECT * FROM users WHERE name = '" + username + "'";
    db.query(sql);
}
