// Insecure TLS: SHOULD trigger the rule
// Pattern: 使用不安全的 SSL/TLS 協議版本或禁用憑證驗證
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import javax.net.ssl.*;

public class InsecureTlsFail {
    public void unsafeProtocol() throws Exception {
        // 不安全：使用已棄用的 SSLv3
        SSLContext ctx = SSLContext.getInstance("SSLv3");

        // 不安全：使用已棄用的 TLSv1.0
        SSLContext ctx2 = SSLContext.getInstance("TLSv1");

        // 不安全：使用已棄用的 TLSv1.1
        SSLContext ctx3 = SSLContext.getInstance("TLSv1.1");
    }

    public void unsafeTrustManager() {
        // 不安全：使用接受所有憑證的 TrustManager
        TrustManager tm = new TrustAllCerts();
    }
}

