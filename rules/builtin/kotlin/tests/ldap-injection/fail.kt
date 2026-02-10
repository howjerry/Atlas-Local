import javax.naming.directory.InitialDirContext

// LDAP Injection: SHOULD trigger the rule
// Pattern: LDAP 搜尋使用字串模板組合 filter

fun findUser(ctx: InitialDirContext, username: String) {
    // 不安全：使用字串模板組合 LDAP filter
    val results = ctx.search("dc=example,dc=com", "(uid=$username)", null)
}

