import java.security.MessageDigest

fun hashPassword(password: String): ByteArray {
    // 不安全：使用弱雜湊演算法 MD5
    val md = MessageDigest.getInstance("MD5")
    return md.digest(password.toByteArray())
}

fun hashData(data: String): ByteArray {
    // 不安全：使用弱雜湊演算法 SHA-1
    val md = MessageDigest.getInstance("SHA-1")
    return md.digest(data.toByteArray())
}
