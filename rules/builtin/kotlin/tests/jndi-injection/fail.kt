import javax.naming.InitialContext

// JNDI Injection: SHOULD trigger the rule
// Pattern: JNDI lookup 使用變數作為名稱參數

fun unsafeLookup(userInput: String) {
    // 不安全：使用變數作為 JNDI lookup 名稱
    val ctx = InitialContext()
    val obj = ctx.lookup(userInput)
}

fun unsafeLookupFromRequest(ctx: InitialContext, resourceName: String) {
    // 不安全：動態 lookup 名稱可能來自使用者輸入
    val dataSource = ctx.lookup(resourceName)
}

