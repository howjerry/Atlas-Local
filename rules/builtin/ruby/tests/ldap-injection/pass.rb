# LDAP Injection: should NOT trigger the rule
# 使用 Net::LDAP::Filter 安全建構 filter

# 安全：使用 Net::LDAP::Filter
filter = Net::LDAP::Filter.eq("uid", username)
ldap.search(filter: filter)

# 安全：使用硬編碼 filter
ldap.search(filter: "(objectClass=user)")

