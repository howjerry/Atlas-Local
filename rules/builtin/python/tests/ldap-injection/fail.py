# LDAP Injection: SHOULD trigger the rule
# Pattern: LDAP search 使用字串格式化組合 filter
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import ldap

def unsafe_ldap_search(conn, username):
    # 不安全：使用字串串接組合 LDAP filter
    conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=" + username + ")")

def unsafe_ldap_bind(conn, dn_input):
    # 不安全：使用字串串接組合 DN
    conn.simple_bind_s("cn=" + dn_input + ",dc=example,dc=com", "password" + dn_input)

