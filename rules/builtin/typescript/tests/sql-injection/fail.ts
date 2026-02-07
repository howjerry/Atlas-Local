// SQL Injection: SHOULD trigger the rule
// Pattern: method call (query/execute/exec/raw/prepare/run) with template string argument

const userId = req.params.id;

const result1 = db.query(`SELECT * FROM users WHERE id = ${userId}`);

const result2 = connection.execute(`DELETE FROM sessions WHERE token = ${token}`);

const result3 = pool.raw(`UPDATE accounts SET balance = ${amount} WHERE user_id = ${uid}`);

const result4 = knex.prepare(`INSERT INTO logs (msg) VALUES ('${message}')`);
