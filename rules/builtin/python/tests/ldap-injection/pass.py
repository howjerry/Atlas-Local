# LDAP Injection: should NOT trigger the rule
# 使用參數化 LDAP filter

import ldap
from ldap.filter import filter_format

def safe_ldap_search(conn, username):
    # 安全：使用 filter_format 進行參數化
    safe_filter = filter_format("(uid=%s)", [username])
    conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, safe_filter)

def safe_ldap_hardcoded(conn):
    # 安全：使用硬編碼的 filter
    conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=admin)")

