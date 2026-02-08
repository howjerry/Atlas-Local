// SQL Injection: should NOT trigger the rule
// Uses parameterized queries with placeholder arguments

package main

import "database/sql"

func safeQueries(db *sql.DB, userId string, token string) {
	db.Query("SELECT * FROM users WHERE id = $1", userId)

	db.Exec("DELETE FROM sessions WHERE token = ?", token)

	db.QueryRow("SELECT name FROM users WHERE id = $1", userId)
}
