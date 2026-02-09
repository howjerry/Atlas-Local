// SSRF: 應該觸發規則
// Pattern: 使用使用者輸入建構 URL 物件
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import java.net.URL;
import java.io.InputStream;

public class SsrfFail {
    // 使用使用者提供的 URL 字串建立 URL 物件（不安全）
    public InputStream fetchUrl(String userUrl) throws Exception {
        URL url = new URL(userUrl);
        return url.openStream();
    }

    // 使用變數建構 URL（不安全）
    public String fetchContent(String endpoint) throws Exception {
        URL targetUrl = new URL(endpoint);
        return targetUrl.getContent().toString();
    }
}
