# SQL Injection: should NOT trigger the rule
# Uses parameterized queries with placeholders

import sqlite3

def safe_query(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

    cursor.execute("DELETE FROM sessions WHERE token = %s", (token,))

    cursor.executemany("INSERT INTO logs VALUES (?)", [(msg,) for msg in messages])

    cursor.execute("SELECT * FROM users WHERE active = 1")
