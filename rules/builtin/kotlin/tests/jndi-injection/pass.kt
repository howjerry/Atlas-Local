import javax.naming.InitialContext

// JNDI Injection: should NOT trigger the rule
// 使用硬編碼的 JNDI 名稱

fun safeLookup() {
    // 安全：使用硬編碼的 JNDI 名稱
    val ctx = InitialContext()
    val ds = ctx.lookup("java:comp/env/jdbc/myDB")
}

fun safeResourceAnnotation() {
    // 安全：使用 Spring @Resource 注入而非程式化 lookup
    val connectionPool = "configured via DI"
}

