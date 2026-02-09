import java.security.MessageDigest

fun hashPassword(password: String): ByteArray {
    // 安全：使用 SHA-256 強雜湊演算法
    val md = MessageDigest.getInstance("SHA-256")
    return md.digest(password.toByteArray())
}

fun encryptData(data: ByteArray): ByteArray {
    // 安全：使用 AES-GCM 強加密演算法
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    return cipher.doFinal(data)
}
