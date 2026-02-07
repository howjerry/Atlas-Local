# SQL Injection: SHOULD trigger the rule
# Pattern: cursor.execute/executemany/executescript with binary_operator (string formatting)
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import sqlite3

def unsafe_query(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)

    cursor.execute("DELETE FROM sessions WHERE token = '%s'" % token)

    cursor.executemany("INSERT INTO logs VALUES ('" + msg + "')", data)

    cursor.executescript("DROP TABLE " + table_name)
