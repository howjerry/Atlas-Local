import javax.net.ssl.SSLContext

// Insecure TLS: SHOULD trigger the rule
// Pattern: 使用過時的 TLS 協定或信任所有憑證

fun createInsecureContext() {
    // 不安全：使用 TLSv1（已棄用）
    val ctx = SSLContext.getInstance("TLSv1")

    // 不安全：使用 TrustAllCerts
    val tm = TrustAllCerts()
}

