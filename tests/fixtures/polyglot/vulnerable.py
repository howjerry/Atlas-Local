"""Python file with known vulnerabilities for polyglot testing.

NOTE: This file INTENTIONALLY contains insecure patterns for SAST test fixtures.
These patterns are here to be DETECTED by the Atlas scanner, not used in production.
"""
import os
import pickle
import sqlite3


def get_user(cursor, user_id: str):
    """SQL injection via f-string -- should trigger atlas/security/python/sql-injection"""
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def run_command(cmd: str):
    """Command injection via os.system -- should trigger atlas/security/python/command-injection"""
    os.system(cmd)


def evaluate(expr: str):
    """Code injection via eval -- should trigger atlas/security/python/eval-usage.
    nosec: SAST test fixture - intentionally vulnerable for scanner testing."""
    return eval(expr)  # noqa: S307 - intentional for SAST testing


def load_data(data: bytes):
    """Unsafe deserialization -- should trigger atlas/security/python/unsafe-deserialization"""
    return pickle.loads(data)
