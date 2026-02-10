# LDAP Injection: SHOULD trigger the rule
# Pattern: LDAP 搜尋使用字串內插組合 filter
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

# 不安全：使用字串內插組合 LDAP filter
ldap.search(filter: "(uid=#{params[:username]})")

# 不安全：bind_as 使用字串內插
ldap.bind_as(filter: "(cn=#{user_input})")

