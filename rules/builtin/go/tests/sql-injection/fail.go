// SQL Injection: SHOULD trigger the rule
// Pattern: Query/Exec/QueryRow with string concatenation via + operator
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

import "database/sql"

func unsafeQueries(db *sql.DB, userId string, token string) {
	db.Query("SELECT * FROM users WHERE id = " + userId)

	db.Exec("DELETE FROM sessions WHERE token = " + token)

	db.QueryRow("SELECT name FROM users WHERE id = " + userId)
}
