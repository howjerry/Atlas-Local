import io.jsonwebtoken.Jwts

// JWT No Verify: SHOULD trigger the rule
// Pattern: JWT 解析跳過簽名驗證

fun parseToken(token: String) {
    // 不安全：使用 parseClaimsJwt 不驗證簽名
    val claims = Jwts.parser().parseClaimsJwt(token).body

    // 不安全：使用 decode 不驗證
    val decoded = JWT.decode(token)
}

