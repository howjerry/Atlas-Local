// Insecure TLS: should NOT trigger the rule
// 使用安全的 TLS 版本和正確的憑證驗證

import javax.net.ssl.*;

public class InsecureTlsPass {
    public void safeProtocol() throws Exception {
        // 安全：使用 TLSv1.2
        SSLContext ctx = SSLContext.getInstance("TLSv1.2");

        // 安全：使用 TLSv1.3
        SSLContext ctx2 = SSLContext.getInstance("TLSv1.3");
    }

    public void safeTrustManager() throws Exception {
        // 安全：使用預設的 TrustManagerFactory
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
    }
}

