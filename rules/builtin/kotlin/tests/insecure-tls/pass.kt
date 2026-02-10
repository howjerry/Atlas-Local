import javax.net.ssl.SSLContext

// Insecure TLS: should NOT trigger the rule
// 使用安全的 TLS 設定

fun createSecureContext() {
    // 安全：使用 TLSv1.3
    val ctx = SSLContext.getInstance("TLSv1.3")
}

