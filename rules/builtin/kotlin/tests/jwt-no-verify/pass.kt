import io.jsonwebtoken.Jwts

// JWT No Verify: should NOT trigger the rule
// 使用正確的 JWT 簽名驗證

fun verifyToken(token: String, key: java.security.Key) {
    // 安全：使用 parseClaimsJws 驗證簽名
    val claims = Jwts.parser().setSigningKey(key).parseClaimsJws(token).body
}

