import java.security.SecureRandom

fun generateToken(): String {
    // 安全：使用密碼學安全的隨機數產生器
    val rng = SecureRandom()
    val bytes = ByteArray(32)
    rng.nextBytes(bytes)
    return bytes.joinToString("") { "%02x".format(it) }
}
