import javax.naming.directory.InitialDirContext

// LDAP Injection: should NOT trigger the rule
// 使用硬編碼 filter 或參數化查詢

fun findUser(ctx: InitialDirContext) {
    // 安全：使用硬編碼 filter
    val results = ctx.search("dc=example,dc=com", "(objectClass=user)", null)
}

