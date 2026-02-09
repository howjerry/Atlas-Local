// SSRF: 不應觸發規則
// 使用硬編碼的 URL 字串

import java.net.URL;
import java.net.URI;
import java.io.InputStream;

public class SsrfPass {
    // 使用硬編碼 URL（安全）
    public InputStream fetchApi() throws Exception {
        URL url = new URL("https://api.example.com/data");
        return url.openStream();
    }

    // 使用 URI 而非直接 URL 建構（安全替代方案）
    public URI buildUri(String path) throws Exception {
        return new URI("https", "api.example.com", path, null);
    }
}
