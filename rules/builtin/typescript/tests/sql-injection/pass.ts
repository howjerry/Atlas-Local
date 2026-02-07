// SQL Injection: should NOT trigger the rule
// Uses parameterized queries instead of template literals

const userId = req.params.id;

const result1 = db.query("SELECT * FROM users WHERE id = $1", [userId]);

const result2 = connection.execute("DELETE FROM sessions WHERE token = ?", [token]);

const result3 = pool.query("UPDATE accounts SET balance = ? WHERE user_id = ?", [amount, uid]);

const result4 = knex("users").where("id", userId).select("*");
